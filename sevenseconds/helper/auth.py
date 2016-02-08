import os
import click
import keyring
import botocore.exceptions
from itertools import repeat
import multiprocessing
from aws_saml_login import authenticate, assume_role, get_boto3_session
from ..helper import ActionOnExit, error, fatal_error
from ..config import AccountData


def get_aws_credentials(saml_batch, saml_user, saml_password):
    if not saml_password:
        saml_password = keyring.get_password('sevenseconds', saml_user)
    if not saml_password:
        saml_password = click.prompt('Please enter your SAML password', hide_input=True)
    credentials = {}
    worker_result = []
    for saml_url in saml_batch:
        with ActionOnExit('Authenticating against {}..'.format(saml_url)):
            saml_xml, roles = authenticate(saml_url, saml_user, saml_password)
            keyring.set_password('sevenseconds', saml_user, saml_password)

        with multiprocessing.Pool(processes=os.cpu_count() * 4) as pool:
            worker_result = pool.starmap(assume_role_worker,
                                         zip(saml_batch[saml_url].values(),
                                             repeat(roles),
                                             repeat(saml_xml)))
    for worker_value in worker_result:
        if isinstance(worker_value, dict):
            credentials.update(worker_value)
    return credentials


def assume_role_worker(batch, roles, saml_xml):
        account_name = batch['name']
        account_alias = batch['alias']
        saml_role = batch['role']
        cred_name = '{}/{}'.format(account_alias, saml_role)
        matching_roles = [(parn, rarn, aname)
                          for parn, rarn, aname in roles if aname == account_alias and rarn.endswith(saml_role)]
        if not matching_roles:
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
            role = matching_roles[0]
            with ActionOnExit('[{}] Assuming role {}..'.format(account_alias, role)):
                key_id, secret, session_token = assume_role(saml_xml, role[0], role[1])
                # boto3.utils not pickalble, save keys and create the Session after
                # multiprocessing.Pool().map()...
                # credentials[batch_entry] = get_boto3_session(key_id, secret, session_token)
                return {cred_name: {
                    'aws_access_key_id': key_id,
                    'aws_secret_access_key': secret,
                    'aws_session_token': session_token
                    }}


def get_sessions(account_names: list, saml_user: str, saml_password: str,
                 config: dict, accounts: list, options: dict):
    global_cfg = config.get('global', {})
    sessions_tmp = {}
    saml_batch = {}

    for account_name in account_names:
        cfg = accounts.get(account_name) or {}
        for key, val in global_cfg.items():
            if key not in cfg:
                cfg[key] = val

        if saml_user:
            saml_url = cfg.get('saml_identity_provider_url')
            saml_role = cfg.get('saml_admin_login_role')
            account_alias = cfg.get('alias', account_name).format(account_name=account_name)
            base_ami = cfg.get('base_ami', {}).get('account_name')
            admin_account = cfg.get('admin_account')
            if not admin_account:
                fatal_error('Missing Option "admin_account" please set Account Name for Main-Account!')
            if not base_ami:
                fatal_error('Missing Option "account_name" for base AMI. Please set Account Name for AMI-Account!')

            if saml_batch.get(saml_url) is None:
                saml_batch[saml_url] = {}
            for account in (admin_account, base_ami, account_alias):
                saml_batch[saml_url]['{}/{}'.format(account, saml_role)] = {
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

    credentials = get_aws_credentials(saml_batch, saml_user, saml_password)

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
