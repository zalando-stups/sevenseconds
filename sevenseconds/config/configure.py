import os
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from itertools import repeat
from multiprocessing import Pool

import boto3

import sevenseconds.helper
from .acm import configure_acm
from .ami import latest_base_images, configure_base_images
from .bastion import configure_bastion_host, delete_bastion_host
from .cloudtrail import configure_cloudtrail_all_regions
from .cloudwatch import configure_log_group
from .ec2 import configure_ebs_encryption
from .elasticache import configure_elasticache
from .iam import configure_iam
from .kms import configure_kms_keys
from .policysimulator import check_policy_simulator
from .rds import configure_rds
from .route53 import configure_dns
from .s3 import configure_s3_buckets
from .securitygroup import configure_security_groups
from .vpc import configure_vpc, if_vpc_empty, cleanup_vpc, delete_nat_host
from ..helper import error, info, ok
from ..helper.aws import get_account_id, get_account_alias, set_account_alias
from ..config import AccountData, SharedData


def start_configuration(sessions: list, trusted_addresses: set, options: dict):
    info('Start Pool processing...')

    # TODO move trusted_addresses to prepare_shared_data
    shared_data = prepare_shared_data(sessions, trusted_addresses)

    with Pool(processes=options.get('max_procs', os.cpu_count())) as pool:
        run_successfully = pool.starmap(configure_account_except, zip(sessions, repeat(shared_data)))
    info('Pool processing done...')
    if all(run_successfully):
        return True
    return False


def prepare_shared_data(sessions: list, trusted_addresses: set):
    """Returns the latest AMI IDs for each configured channel for all used regions"""
    ami_session = boto3.session.Session(**sessions[0].ami_session)
    ami_config = sessions[0].config['base_ami']
    default_channel = ami_config['default_channel']

    images = {}
    for session in sessions:
        if session.config['base_ami'] != ami_config:
            raise Exception("base_ami config overrides are unsupported")

        for region in session.config['regions']:
            if region not in images:
                images[region] = latest_base_images(ami_session, region, ami_config)
                if default_channel not in images[region]:
                    raise Exception("Unable to find default base AMI {} for region {}".format(default_channel, region))
    return SharedData(images, trusted_addresses)


def configure_account_except(session_data: AccountData, shared_data: SharedData):
    try:
        configure_account(session_data, shared_data)
        return True
    except Exception as e:
        error(traceback.format_exc())
        error(e)
        return False


def configure_account(session_data: AccountData, shared_data: SharedData):
    start_time = time.time()
    sevenseconds.helper.THREADDATA.name = session_data.name
    session = {}
    for session_name in ('session', 'admin_session', 'ami_session'):
        session[session_name] = boto3.session.Session(**getattr(session_data, session_name))
    account = session_data._replace(id=get_account_id(session['session']), **session)
    del (session)
    # Remove Default-Session
    boto3.DEFAULT_SESSION = None
    # account_id = get_account_id(session['account'])
    # info('Account ID is {}'.format(account_id))
    account_alias_from_aws = get_account_alias(account.session)
    if len(account_alias_from_aws) == 0:
        set_account_alias(account.session, account.alias)
    elif account.alias != account_alias_from_aws[0]:
        error('Connected to "{}", but account "{}" should be configured'.format(account_alias_from_aws, account.alias))
        return

    # check_policy_simulator exit this script with a fatal_error, if it found an error
    check_policy_simulator(account)

    configure_cloudtrail_all_regions(account)
    configure_dns(account)
    configure_iam(account)
    configure_s3_buckets(account)

    regions = account.config['regions']

    futures = []
    if len(regions) > 0:
        with ThreadPoolExecutor(max_workers=len(regions)) as executor:
            for region in regions:
                futures.append(executor.submit(configure_account_region, account, region, shared_data))
    for future in futures:
        # will raise an exception if the jobs failed
        future.result()
    ok('Done with {} / {} after {}'.format(account.id, account.name, timedelta(seconds=time.time() - start_time)))


def configure_account_region(account: object, region: str, shared_data: SharedData):
    sevenseconds.helper.THREADDATA.name = '{}|{}'.format(account.name, region)

    base_images = shared_data.base_images.get(region, {})
    default_base_ami = base_images[account.config['base_ami']['default_channel']]

    configure_log_group(account.session, region, account.config)
    configure_acm(account, region)
    configure_kms_keys(account, region)
    configure_ebs_encryption(account, region)
    configure_base_images(account, region, base_images)
    vpc = configure_vpc(account, region, default_base_ami)
    configure_bastion_host(account, vpc, region, default_base_ami)
    configure_elasticache(account.session, region, vpc)
    configure_rds(account.session, region, vpc)
    configure_security_groups(account, region, shared_data.trusted_addresses, vpc)


def start_cleanup(region: str, sessions: list, options: dict):
    info('Start Pool processing...')
    with Pool(processes=options.get('max_procs', os.cpu_count())) as pool:
        pool.starmap(cleanup_account_except, zip(sessions.values(), repeat(region)))
    info('Pool processing done... ')


def cleanup_account_except(session_data: AccountData, region: str):
    try:
        cleanup_account(session_data, region)
    except Exception as e:
        error(traceback.format_exc())
        error(e)


def cleanup_account(session_data: AccountData, region: str):
    start_time = time.time()
    sevenseconds.helper.THREADDATA.name = session_data.name
    session = {}
    for session_name in ('session', 'admin_session', 'ami_session'):
        session[session_name] = boto3.session.Session(**getattr(session_data, session_name))
    account = session_data._replace(id=get_account_id(session['session']), **session)
    del (session)
    # Remove Default-Session
    boto3.DEFAULT_SESSION = None
    # account_id = get_account_id(session['account'])
    # info('Account ID is {}'.format(account_id))

    account_alias_from_aws = get_account_alias(account.session)
    if len(account_alias_from_aws) > 0 and account.alias != account_alias_from_aws[0]:
        error('Connected to "{}", but account "{}" should be configured'.format(account_alias_from_aws, account.alias))
        return

    cleanup_account_region(account, region)

    ok('Done with {} / {} after {}'.format(account.id, account.name, timedelta(seconds=time.time() - start_time)))


def cleanup_account_region(account: object, region: str):
    sevenseconds.helper.THREADDATA.name = '{}|{}'.format(account.name, region)
    if if_vpc_empty(account, region):
        info('Region IS empty. Start clean up!')
        if not account.dry_run:
            delete_bastion_host(account, region)
            delete_nat_host(account, region)
            cleanup_vpc(account, region)
    else:
        error('Region is not empty. Skip clean up!')

    # vpc = configure_vpc(account, region)
    # configure_bastion_host(account, vpc, region)
    # configure_elasticache(account.session, region, vpc)
    # configure_rds(account.session, region, vpc)
    # configure_security_groups(account, region, trusted_addresses)
