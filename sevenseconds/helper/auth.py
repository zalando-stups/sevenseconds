import os
import jwt
import botocore.exceptions
import requests
import zign.api
from itertools import repeat
import multiprocessing
from aws_saml_login import get_boto3_session
from ..helper import ActionOnExit, error, fatal_error
from ..config import AccountData

MANAGED_ID_KEY = 'https://identity.zalando.com/managed-id'
RESOURCES = {'credentials': '/aws-accounts/{account_id}/roles/{role_name}/credentials',
             'roles':       '/aws-account-roles/{user_id}'}


def get_profiles(service_url):
    '''Returns the AWS profiles for a user.

    User is implicit from ztoken'''

    token = zign.api.get_token('sevenseconds', ['uid'])
    decoded_token = jwt.decode(token, verify=False)

    if MANAGED_ID_KEY not in decoded_token:
        raise ValueError('Invalid token. Please check your ztoken configuration')

    roles_url = service_url + RESOURCES['roles'].format(user_id=decoded_token[MANAGED_ID_KEY])

    r = requests.get(roles_url, headers={'Authorization': 'Bearer {}'.format(token)}, timeout=20)
    r.raise_for_status()

    return r.json()['account_roles']


def get_profile(account_name, role_name, service_url):
    '''Returns the profile information for the given role and account name.'''

    profiles = get_profiles(service_url)

    for item in profiles:
        if item['account_name'] == account_name and item['role_name'] == role_name:
            return item

    return None


def get_aws_credentials_from_aws_credentials_service(account_name, role_name, service_url):
    '''Requests the specified AWS Temporary Credentials from the provided Credential Service URL'''

    profile = get_profile(account_name, role_name, service_url)

    credentials_url = service_url + RESOURCES['credentials'].format(account_id=profile['account_id'],
                                                                    role_name=role_name)

    token = zign.api.get_token('sevenseconds', ['uid'])

    r = requests.get(credentials_url, headers={'Authorization': 'Bearer {}'.format(token)},
                     timeout=30)
    r.raise_for_status()

    return r.json()


def get_aws_credentials(batch):
    credentials = {}
    worker_result = []
    for aws_credentials_service_url in batch:
        with ActionOnExit('Authenticating against {}..'.format(aws_credentials_service_url)):
            profiles = get_profiles(aws_credentials_service_url)

        with multiprocessing.Pool(processes=os.cpu_count() * 4) as pool:
            worker_result = pool.starmap(assume_role_worker,
                                         zip(batch[aws_credentials_service_url].values(),
                                             repeat(profiles),
                                             repeat(aws_credentials_service_url)))
    for worker_value in worker_result:
        if isinstance(worker_value, dict):
            credentials.update(worker_value)
    return credentials


def assume_role_worker(batch, profiles, aws_credentials_service_url):
        account_name = batch['name']
        account_alias = batch['alias']
        saml_role = batch['role']
        cred_name = '{}/{}'.format(account_alias, saml_role)
        role_name = saml_role.split('-')[-1]
        matching_profile = None
        for profile in profiles:
            # FIXME: this comparison might be dangerous!
            if account_alias.endswith(profile['account_name']) and profile['role_name'] == role_name:
                matching_profile = profile
        if not matching_profile:
            error('[{}] No matching role found for account {}/{}. Try profile from ~/.aws/credentials'
                  .format(account_alias, account_alias, saml_role))
            for profile_name in (account_alias, account_name):
                try:
                    if get_boto3_session(None, None, profile=profile_name):
                        return {cred_name: {'profile_name': profile_name}}
                except botocore.exceptions.ProfileNotFound as e:
                    error('[{}] {}'
                          .format(account_alias, e))

        else:
            profile = matching_profile
            with ActionOnExit('[{}] Assuming role {}..'.format(account_alias, profile['role_name'])):
                credentials = get_aws_credentials_from_aws_credentials_service(
                    profile['account_name'], profile['role_name'], aws_credentials_service_url)
                # boto3.utils not pickalble, save keys and create the Session after
                # multiprocessing.Pool().map()...
                # credentials[batch_entry] = get_boto3_session(key_id, secret, session_token)
                return {cred_name: {
                    'aws_access_key_id': credentials['access_key_id'],
                    'aws_secret_access_key': credentials['secret_access_key'],
                    'aws_session_token': credentials['session_token']
                }}


def get_sessions(account_names: list,
                 config: dict, accounts: list, options: dict):
    global_cfg = config.get('global', {})
    sessions_tmp = {}
    batch = {}

    for account_name in account_names:
        cfg = accounts.get(account_name) or {}
        for key, val in global_cfg.items():
            if key not in cfg:
                cfg[key] = val

        aws_credentials_service_url = cfg.get('aws_credentials_service_url')
        saml_role = cfg.get('saml_admin_login_role')
        account_alias = cfg.get('alias', account_name).format(account_name=account_name)
        base_ami = cfg.get('base_ami', {}).get('account_name')
        admin_account = cfg.get('admin_account')
        if not admin_account:
            fatal_error('Missing Option "admin_account" please set Account Name for Main-Account!')
        if not base_ami:
            fatal_error('Missing Option "account_name" for base AMI. Please set Account Name for AMI-Account!')

        if batch.get(aws_credentials_service_url) is None:
            batch[aws_credentials_service_url] = {}
        for account in (admin_account, base_ami, account_alias):
            batch[aws_credentials_service_url]['{}/{}'.format(account, saml_role)] = {
                'name': account_name,
                'role': saml_role,
                'alias': account}
        sessions_tmp[account_alias] = {
            'admin_account_keyname': '{}/{}'.format(admin_account, saml_role),
            'base_ami_account_keyname': '{}/{}'.format(base_ami, saml_role),
            'account_keyname': '{}/{}'.format(account_alias, saml_role),
            'account_name': account_name,
            'account_alias': account_alias,
            'config': cfg}

    credentials = get_aws_credentials(batch)

    return rewrite_sessions_map(sessions_tmp, credentials, options)


def rewrite_sessions_map(sessions_tmp: dict, credentials: dict, options: dict):
    sessions = {}
    for account_alias in sessions_tmp:
        account_keyname = sessions_tmp[account_alias]['account_keyname']
        admin_account_keyname = sessions_tmp[account_alias]['admin_account_keyname']
        base_ami_account_keyname = sessions_tmp[account_alias]['base_ami_account_keyname']
        if credentials.get(account_keyname):
            sessions[account_alias] = AccountData(name=sessions_tmp[account_alias]['account_name'],
                                                  alias=sessions_tmp[account_alias]['account_alias'],
                                                  id=None,
                                                  session=credentials[account_keyname],
                                                  admin_session=credentials[admin_account_keyname],
                                                  ami_session=credentials[base_ami_account_keyname],
                                                  config=sessions_tmp[account_alias]['config'],
                                                  dry_run=options.get('dry_run', False),
                                                  options=options)

    return sessions
