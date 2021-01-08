import jwt
import zign.api
import requests
import os
import boto3
import botocore.exceptions
import multiprocessing
from itertools import repeat
from ..helper import ActionOnExit, error, fatal_error


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
                 token_managed_id_key: str,
                 login_account: str,
                 role_name: str,
                 token: str):
        if token:
            self.token = token
        else:
            self.token = zign.api.get_token('sevenseconds', ['uid'])
        self.service_url = aws_credentials_service_url
        self.service_resources = aws_credentials_service_resources
        self.account_list_url = account_list_url
        self.token_managed_id_key = token_managed_id_key
        self.decoded_token = jwt.decode(self.token, options={"verify_signature": False})

        if self.token_managed_id_key not in self.decoded_token:
            raise ValueError('Invalid token. Please check your ztoken configuration')
        self.user_id = self.decoded_token[self.token_managed_id_key]
        self._profiles = []
        self._accounts = []
        self.get_aws_accounts()
        self.get_profiles()

        self.use_master_account = False
        if login_account is not None:

            self.use_master_account = True
            self.master_account = login_account
            with ActionOnExit('Log in to Master Accounter..'):
                self.master_credentials = self.get_aws_credentials_from_aws_credentials_service(
                    self.master_account,
                    role_name
                )

    def get_profiles(self):
        '''Returns the AWS profiles for a user.

        User is implicit from ztoken'''
        if self._profiles:
            return self._profiles
        with ActionOnExit('Contact to AWS Credential Service and get list of all profiles'):
            roles_url = self.service_url + self.service_resources['roles'].format(user_id=self.user_id)

            r = requests.get(roles_url, headers={'Authorization': 'Bearer {}'.format(self.token)}, timeout=20)
            r.raise_for_status()

            self._profiles = r.json()['account_roles']
        return self._profiles

    def get_profile(self, account_name, role_name):
        '''Returns the profile information for the given role and account name.'''
        self.get_profiles()
        for item in self._profiles:
            if item['account_name'] == account_name and item['role_name'] == role_name:
                return item
        else:
            raise RuntimeError('Unable to find the role: {} for account: {}'.format(role_name, account_name))

    def get_aws_credentials(self, account_name, role_name):
        '''Requests the specified AWS Temporary Credentials'''
        self.get_profiles()
        if self.use_master_account:
            try:
                return self.get_aws_credentials_from_master_account(account_name, role_name)
            except Exception:
                error('[{}] No matching role found for account {}/{}. Try profile from ~/.aws/credentials'
                      .format(account_name, account_name, role_name))
                return self.get_aws_credentials_from_profile(account_name)
        else:
            for profile in self._profiles:
                if account_name == profile['account_name'] and profile['role_name'] == role_name:
                    return self.get_aws_credentials_from_aws_credentials_service(
                        profile['account_name'],
                        profile['role_name'])
            error('[{}] No matching role found for account {}/{}. Try profile from ~/.aws/credentials'
                  .format(account_name, account_name, role_name))
            return self.get_aws_credentials_from_profile(account_name)

    def get_aws_credentials_from_profile(self, account_name):
        try:
            if boto3.session.Session(profile_name=account_name):
                return {'profile_name': account_name}
        except botocore.exceptions.ProfileNotFound as e:
            error('[{}] {}'
                  .format(account_name, e))
            return None

    def get_aws_credentials_from_master_account(self, account_name, role_name):
        account = self.get_aws_account(account_name)
        with ActionOnExit('[{}] Assuming role {} via {}..'.format(account_name, role_name, self.master_account)):
            sts = boto3.client('sts', **self.master_credentials)
            role_arn = 'arn:aws:iam::{}:role/{}'.format(
                account['id'],
                role_name)
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName='sevenseconds'
            )
        return {
                    'aws_access_key_id': response['Credentials'].get('AccessKeyId'),
                    'aws_secret_access_key': response['Credentials'].get('SecretAccessKey'),
                    'aws_session_token': response['Credentials'].get('SessionToken')
                }

    def get_aws_credentials_from_aws_credentials_service(self, account_name, role_name):
        '''Requests the specified AWS Temporary Credentials from the provided Credential Service URL'''
        role_name = role_name.split('-', 1)[-1]
        profile = self.get_profile(account_name, role_name)
        with ActionOnExit('[{}] Assuming role {}..'.format(account_name, profile['role_name'])):
            credentials_url = self.service_url + self.service_resources['credentials'].format(
                account_id=profile['account_id'],
                role_name=role_name)
            r = requests.get(credentials_url, headers={'Authorization': 'Bearer {}'.format(self.token)},
                             timeout=30)

            r.raise_for_status()

            credentials = r.json()
        return {
                    'aws_access_key_id': credentials.get('access_key_id'),
                    'aws_secret_access_key': credentials.get('secret_access_key'),
                    'aws_session_token': credentials.get('session_token')
                }

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
        if len(self._accounts) == 0:
            with ActionOnExit('get AWS Accounts from {}'.format(self.account_list_url)) as act:
                r = requests.get(
                    self.account_list_url,
                    headers={'Authorization': 'Bearer {}'.format(self.token)},
                    timeout=20)
                r.raise_for_status()
                self._accounts = r.json()
                act.ok('Count: {}'.format(len(self._accounts)))
        return self._accounts

    def get_aws_account(self, account_name):
        for account in self.get_aws_accounts():
            if account['name'] == account_name:
                return account


def get_credentials_map(batch, auth):
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
    role = batch['role']
    cred_name = '{}/{}'.format(account_name, role)
    credentials = auth.get_aws_credentials(account_name, role)
    if credentials:
        return {cred_name: credentials}
    return None


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
                token_managed_id_key=cfg.get('token_managed_id_key'),
                login_account=options.get('login_account', None),
                role_name=saml_role,
                token=options.get('token')
            )
        if batch.get(aws_credentials_service_url) is None:
            batch[aws_credentials_service_url] = {}
        for account in (admin_account, base_ami, account_name):
            batch[aws_credentials_service_url]['{}/{}'.format(account, saml_role)] = {
                'name': account,
                'role': saml_role}
        sessions_tmp[account_name] = {
            'admin_account_keyname': '{}/{}'.format(admin_account, saml_role),
            'base_ami_account_keyname': '{}/{}'.format(base_ami, saml_role),
            'account_keyname': '{}/{}'.format(account_name, saml_role),
            'account_name': account_name,
            'account_alias': account_alias,
            'config': cfg,
            'auth': auth[aws_credentials_service_url]}

    credentials = get_credentials_map(batch, auth)

    return rewrite_sessions_map(sessions_tmp, credentials, options)


def rewrite_sessions_map(sessions_tmp: dict, credentials: dict, options: dict):
    from ..config import AccountData

    sessions = {}
    for account_name in sessions_tmp:
        account_keyname = sessions_tmp[account_name]['account_keyname']
        admin_account_keyname = sessions_tmp[account_name]['admin_account_keyname']
        base_ami_account_keyname = sessions_tmp[account_name]['base_ami_account_keyname']
        if credentials.get(account_keyname):
            sessions[account_name] = AccountData(name=sessions_tmp[account_name]['account_name'],
                                                 alias=sessions_tmp[account_name]['account_alias'],
                                                 id=None,
                                                 session=credentials[account_keyname],
                                                 admin_session=credentials[admin_account_keyname],
                                                 ami_session=credentials[base_ami_account_keyname],
                                                 config=sessions_tmp[account_name]['config'],
                                                 auth=sessions_tmp[account_name]['auth'],
                                                 dry_run=options.get('dry_run', False),
                                                 options=options)

    return sessions
