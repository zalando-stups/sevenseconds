import boto3
import os
from itertools import repeat
from multiprocessing import Pool
import traceback
from collections import namedtuple
import time
from datetime import timedelta
from ..helper import error, info, ok
from ..helper.aws import get_account_id, get_account_alias, set_account_alias
from .policysimulator import check_policy_simulator
from .cloudtrail import configure_cloudtrail_all_regions
from .route53 import configure_dns
from .acm import configure_acm
from .ses import configure_ses
from .iam import configure_iam
from .s3 import configure_s3_buckets
from .kms import configure_kms_keys
from .cloudwatch import configure_log_group
from .vpc import configure_vpc, if_vpc_empty, cleanup_vpc, delete_nat_host
from .bastion import configure_bastion_host, delete_bastion_host
from .elasticache import configure_elasticache
from .rds import configure_rds
from .securitygroup import configure_security_groups
from concurrent.futures import ThreadPoolExecutor
import sevenseconds.helper

AccountData = namedtuple(
    'AccountData',
    (
        'name',             # Short Name of this Account
        'alias',            # Full AWS Account Alias Name (prefix + name)
        'id',               # AWS Account ID
        'session',          # Boto3 Session for the current Account
        'admin_session',    # Boto3 Session for the Admin Account (for DNS deligation)
        'ami_session',      # Boto3 Session of the Taupage Owner Accounts (for EC2 AMI)
        'config',           # Configuration of the current Account
        'dry_run',          # dry-run boolean Flag
        'options',          # Command Options dict
        'auth'              # OAuthServices Object (exp. for Account List and AWS Credentials Service)
    ))


def start_configuration(sessions: list, trusted_addresses: set, options: dict):
    info('Start Pool processing...')
    with Pool(processes=options.get('max_procs', os.cpu_count())) as pool:
        run_successfully = pool.starmap(configure_account_except, zip(sessions.values(), repeat(trusted_addresses)))
    info('Pool processing done...')
    if all(run_successfully):
        return True
    return False


def configure_account_except(session_data: AccountData, trusted_addresses: set):
    try:
        configure_account(session_data, trusted_addresses)
        return True
    except Exception as e:
        error(traceback.format_exc())
        error(e)
        return False


def configure_account(session_data: AccountData, trusted_addresses: set):
    start_time = time.time()
    sevenseconds.helper.THREADDATA.name = session_data.name
    session = {}
    for session_name in ('session', 'admin_session', 'ami_session'):
        session[session_name] = boto3.session.Session(**getattr(session_data, session_name))
    account = session_data._replace(id=get_account_id(session['session']), **session)
    del(session)
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
    dns_domain = configure_dns(account)
    configure_iam(account, dns_domain)
    configure_s3_buckets(account)
    configure_ses(account, dns_domain)

    regions = account.config['regions']

    futures = []
    if len(regions) > 0:
        with ThreadPoolExecutor(max_workers=len(regions)) as executor:
            for region in regions:
                futures.append(executor.submit(configure_account_region, account, region, trusted_addresses))
    for future in futures:
        # will raise an exception if the jobs failed
        future.result()
    ok('Done with {} / {} after {}'.format(account.id, account.name, timedelta(seconds=time.time() - start_time)))


def configure_account_region(account: object, region: str, trusted_addresses: set):
    sevenseconds.helper.THREADDATA.name = '{}|{}'.format(account.name, region)
    configure_log_group(account.session, region)
    configure_acm(account, region)
    configure_kms_keys(account, region)
    vpc = configure_vpc(account, region)
    configure_bastion_host(account, vpc, region)
    configure_elasticache(account.session, region, vpc)
    configure_rds(account.session, region, vpc)
    configure_security_groups(account, region, trusted_addresses, vpc)


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
    del(session)
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
