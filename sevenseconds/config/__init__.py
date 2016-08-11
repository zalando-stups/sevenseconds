import boto3
import os
from itertools import repeat
from multiprocessing import Pool
import traceback
from collections import namedtuple
import time
from datetime import timedelta
from ..helper import error, info, ok
from ..helper.aws import get_account_id, get_account_alias
from .policysimulator import check_policy_simulator
from .cloudtrail import configure_cloudtrail_all_regions
from .route53 import configure_dns
from .acm import configure_acm
from .ses import configure_ses
from .iam import configure_iam
from .s3 import configure_s3_buckets
from .cloudwatch import configure_log_group
from .vpc import configure_vpc, if_vpc_empty, cleanup_vpc, delete_nat_host
from .bastion import configure_bastion_host, delete_bastion_host
from .elasticache import configure_elasticache
from .rds import configure_rds
from .securitygroup import configure_security_groups
from ..helper.threading import ThreadWorker, Queue
import sevenseconds.helper

AccountData = namedtuple(
    'AccountData',
    (
        'name',
        'alias',
        'id',
        'session',
        'admin_session',
        'ami_session',
        'config',
        'dry_run',
        'options'
    ))


def start_configuration(sessions: list, trusted_addresses: set, options: dict):
    info('Start Pool processing...')
    with Pool(processes=options.get('max_procs', os.cpu_count())) as pool:
        pool.starmap(configure_account_except, zip(sessions.values(), repeat(trusted_addresses)))
    info('Pool processing done... ')


def configure_account_except(session_data: AccountData, trusted_addresses: set):
    try:
        configure_account(session_data, trusted_addresses)
    except Exception as e:
        error(traceback.format_exc())
        error(e)


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
    if account.alias != account_alias_from_aws:
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
    # Create a queue to communicate with the worker threads
    queue = Queue()
    # Create X worker threads
    for x in range(len(regions)):
        worker = ThreadWorker(queue, configure_account_region)
        # Setting daemon to True will let the main thread exit even though the workers are blocking
        worker.daemon = True
        worker.start()
    # Put the tasks into the queue as a tuple
    for region in regions:
        queue.put((account, region, trusted_addresses))
    queue.join()
    ok('Done with {} / {} after {}'.format(account.id, account.name, timedelta(seconds=time.time() - start_time)))


def configure_account_region(account: object, region: str, trusted_addresses: set):
    sevenseconds.helper.THREADDATA.name = '{}|{}'.format(account.name, region)
    configure_log_group(account.session, region)
    configure_acm(account, region)
    vpc = configure_vpc(account, region)
    configure_bastion_host(account, vpc, region)
    configure_elasticache(account.session, region, vpc)
    configure_rds(account.session, region, vpc)
    configure_security_groups(account, region, trusted_addresses)


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
    if account.alias != account_alias_from_aws:
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
