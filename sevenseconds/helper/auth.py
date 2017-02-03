import jwt
import zign.api
import requests
import os
import boto3
import botocore.exceptions
import multiprocessing
from itertools import repeat
from ..helper import ActionOnExit, error, fatal_error
from ..config import AccountData


class AssumeRoleFailed(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'Assuming role failed: {}'.format(self.msg)


class OAuthServices:
    def __init__(self,
                 aws_credentials_service_url: str,
                 aws_credentials_service_resources: dict,
                 account_list_url: str,
                 token_managed_id_key: str):
        self.token = zign.api.get_token('sevenseconds', ['uid'])
        self.service_url = aws_credentials_service_url
        self.service_resources = aws_credentials_service_resources
        self.account_list_url = account_list_url
        self.token_managed_id_key = token_managed_id_key
        self.decoded_token = jwt.decode(self.token, verify=False)

        if self.token_managed_id_key not in self.decoded_token:
            raise ValueError('Invalid token. Please check your ztoken configuration')
        self.user_id = self.decoded_token[self.token_managed_id_key]

    def get_profiles(self):
        '''Returns the AWS profiles for a user.

        User is implicit from ztoken'''
        roles_url = self.service_url + self.service_resources['roles'].format(user_id=self.user_id)

        r = requests.get(roles_url, headers={'Authorization': 'Bearer {}'.format(self.token)}, timeout=20)
        r.raise_for_status()

        return r.json()['account_roles']

    def get_profile(self, account_name, role_name):
        '''Returns the profile information for the given role and account name.'''

        profiles = self.get_profiles()

        for item in profiles:
            if item['account_name'] == account_name and item['role_name'] == role_name:
                return item

        return None

    def get_aws_credentials_from_aws_credentials_service(self, account_name, role_name):
        '''Requests the specified AWS Temporary Credentials from the provided Credential Service URL'''

        profile = self.get_profile(account_name, role_name)

        credentials_url = self.service_url + self.service_resources['credentials'].format(
            account_id=profile['account_id'],
            role_name=role_name)

        r = requests.get(credentials_url, headers={'Authorization': 'Bearer {}'.format(self.token)},
                         timeout=30)
        r.raise_for_status()

        return r.json()

    def get_aws_accounts(self):
        '''Returns a list of all AWS Accounts
        Get Accounts with Account ID from Account API
        http https://cmdb.example.org/aws-accounts.json
        [
            {
                "name": "account_foo",
                "disabled": false,
                "id": "123456789012",
            },
            {
                "name": "account_bar",
                "disabled": true,
                "id": "123123123123",
            }
        ]
        '''
        r = requests.get(self.account_list_url, headers={'Authorization': 'Bearer {}'.format(self.token)}, timeout=20)
        r.raise_for_status()
        return r.json()


def get_aws_credentials(batch, auth):
    credentials = {}
    worker_result = []
    for aws_credentials_service_url in batch:
        with ActionOnExit('Authenticating against {}..'.format(aws_credentials_service_url)):
            profiles = auth[aws_credentials_service_url].get_profiles()

        with multiprocessing.Pool(processes=os.cpu_count() * 4) as pool:
            worker_result = pool.starmap(assume_role_worker,
                                         zip(batch[aws_credentials_service_url].values(),
                                             repeat(profiles),
                                             repeat(auth[aws_credentials_service_url])))
    for worker_value in worker_result:
        if isinstance(worker_value, dict):
            credentials.update(worker_value)
    return credentials


def assume_role_worker(batch, profiles, auth):
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
                if boto3.session.Session(profile_name=profile_name):
                    return {cred_name: {'profile_name': profile_name}}
            except botocore.exceptions.ProfileNotFound as e:
                error('[{}] {}'
                      .format(account_alias, e))

    else:
        profile = matching_profile
        with ActionOnExit('[{}] Assuming role {}..'.format(account_alias, profile['role_name'])):
            credentials = auth.get_aws_credentials_from_aws_credentials_service(
                profile['account_name'], profile['role_name'])
            # boto3.utils not pickalble, save keys and create the Session after
            # multiprocessing.Pool().map()...
            return {cred_name: {
                'aws_access_key_id': credentials.get('access_key_id'),
                'aws_secret_access_key': credentials.get('secret_access_key'),
                'aws_session_token': credentials.get('session_token')
                }}


def get_sessions(account_names: list,
                 config: dict, accounts: list, options: dict):
    global_cfg = config.get('global', {})
    sessions_tmp = {}
    batch = {}
    auth = {}

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

        if auth.get(aws_credentials_service_url) is None:
            auth[aws_credentials_service_url] = OAuthServices(
                aws_credentials_service_url=aws_credentials_service_url,
                aws_credentials_service_resources=cfg.get('aws_credentials_service_resources', {}),
                account_list_url=cfg.get('account_list_url'),
                token_managed_id_key=cfg.get('token_managed_id_key')
            )
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
            'config': cfg,
            'auth': auth[aws_credentials_service_url]}

    credentials = get_aws_credentials(batch, auth)

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
                                                  auth=sessions_tmp[account_alias]['auth'],
                                                  dry_run=options.get('dry_run', False),
                                                  options=options)

    return sessions
