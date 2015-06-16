import fnmatch
import traceback
import click
import keyring
import yaml
import socket
import os
import sys
from sevenseconds.aws import configure_account, destroy_account, get_az_names, get_role_ldif

import sevenseconds
from clickclick import AliasedGroup, error, Action, info, warning
from aws_saml_login import authenticate, assume_role, write_aws_credentials


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('AWS Account Configurator {}'.format(sevenseconds.__version__))
    ctx.exit()


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True)
def cli():
    pass


def get_trusted_addresses(config: dict):
    accounts = config.get('accounts', {})

    addresses = set()

    for name, cidr in config.get('global', {}).get('trusted_networks', {}).items():
        info('Adding trusted network {} ({})'.format(name, cidr))
        addresses.add(cidr)

    for account_name, _cfg in accounts.items():
        cfg = {}
        cfg.update(config.get('global', {}))
        if _cfg:
            cfg.update(_cfg)
        for region in cfg['regions']:
            domains = set(['odd-{}.{}'.format(region, cfg.get('domain').format(account_name=account_name))])
            for az in get_az_names(region):
                domains.add('nat-{}.{}'.format(az, cfg.get('domain').format(account_name=account_name)))
            for domain in sorted(domains):
                with Action('Checking {}'.format(domain)) as act:
                    try:
                        ai = socket.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
                    except:
                        ai = []
                        act.error('n/a')
                        pass
                    for _, _, _, _, ip_port in ai:
                        ip, _ = ip_port
                        addresses.add('{}/32'.format(ip))

    return addresses


@cli.command()
@click.argument('file', type=click.File('rb'))
@click.argument('region_name')
@click.argument('security_group')
def update_security_group(file, region_name, security_group):
    '''Update a Security Group and allow access from all trusted networks, NAT instances and bastion hosts'''
    config = yaml.safe_load(file)

    addresses = get_trusted_addresses(config)

    info('\n'.join(sorted(addresses)))

    update_security_group(region_name, security_group, addresses)


@cli.command()
@click.argument('file', type=click.File('rb'))
@click.argument('account_name_pattern', nargs=-1)
@click.option('--saml-user', help='SAML username', envvar='SAML_USER')
@click.option('--saml-password', help='SAML password (use the environment variable "SAML_PASSWORD")',
              envvar='SAML_PASSWORD')
@click.option('--dry-run', is_flag=True)
def configure(file, account_name_pattern, saml_user, saml_password, dry_run):
    '''Configure one or more AWS account(s) matching the provided pattern

       ACCOUNT_NAME_PATTERN are Unix shell style:

       \b
         *       matches everything
         ?       matches any single character
         [seq]   matches any character in seq
         [!seq]  matches any char not in seq

        Posible Enviroment Variables
        AWS_PROFILE     Connect to this Profile without SAML
        SSLDIR          Directory with all SSL-Files
    '''
    config = yaml.safe_load(file)
    accounts = config.get('accounts', {})
    account_names = []
    for pattern in account_name_pattern:
        account_names.extend(sorted(fnmatch.filter(accounts.keys(), pattern)))

    if not account_names:
        error('No configuration found for account {}'.format(', '.join(account_name_pattern)))
        return
    info('Start configuration of: {}'.format(', '.join(account_names)))
    trusted_addresses = None

    global_cfg = config.get('global', {})
    saml_url = global_cfg.get('saml_identity_provider_url')
    saml_role = global_cfg.get('saml_admin_login_role')

    if saml_user and saml_url and saml_role:
        admin_account = global_cfg.get('admin_account')
        if not admin_account:
            error('Missing Option "admin_account" please set Account Name for Main-Account!')
        else:
            get_aws_credentials(saml_user, saml_password, saml_url, saml_role, admin_account, 'adminaccount')
        base_ami = global_cfg['base_ami']
        get_aws_credentials(saml_user, saml_password, saml_url, saml_role, base_ami['account_name'], 'base_ami_account')

    for account_name in account_names:
        cfg = accounts.get(account_name) or {}
        for key, val in global_cfg.items():
            if key not in cfg:
                cfg[key] = val

        saml_url = cfg.get('saml_identity_provider_url')
        saml_role = cfg.get('saml_admin_login_role')

        if saml_user and saml_url and saml_role:
            account_alias = cfg.get('alias', account_name).format(account_name=account_name)
            aws_profile = 'sevenseconds-{}'.format(account_name)
            if not get_aws_credentials(saml_user, saml_password, saml_url, saml_role, account_alias, aws_profile):
                warning('Skipping account configuration of {} due to missing credentials'.format(account_name))
                continue
            os.environ['AWS_PROFILE'] = aws_profile

        if not trusted_addresses:
            trusted_addresses = get_trusted_addresses(config)

        try:
            configure_account(account_name, cfg, trusted_addresses, dry_run)
        except Exception:
            error('Error while configuring {}: {}'.format(account_name, traceback.format_exc()))


def get_aws_credentials(saml_user, saml_password, saml_url, saml_role, account_alias, credential_name):
    if not saml_password:
        saml_password = keyring.get_password('sevenseconds', saml_user)
    if not saml_password:
        saml_password = click.prompt('Please enter your SAML password', hide_input=True)
    with Action('[{}] Authenticating against {}..'.format(credential_name, saml_url)):
        saml_xml, roles = authenticate(saml_url, saml_user, saml_password)
    keyring.set_password('sevenseconds', saml_user, saml_password)
    matching_roles = [(parn, rarn, aname)
                      for parn, rarn, aname in roles if aname == account_alias and rarn.endswith(saml_role)]
    if not matching_roles:
        error('[{}] No matching role found for account {}'.format(credential_name, account_alias))
        return False
    else:
        role = matching_roles[0]
        with Action('[{}] Assuming role {}..'.format(credential_name, role)):
            key_id, secret, session_token = assume_role(saml_xml, role[0], role[1])
        write_aws_credentials(credential_name, key_id, secret, session_token)
        return True


@cli.command('role-ldif')
@click.argument('configuration-file', type=click.File('rb'))
@click.argument('account_name_pattern', nargs=-1)
@click.option('--saml-user', help='SAML username', envvar='SAML_USER')
@click.option('--saml-password', help='SAML password (use the environment variable "SAML_PASSWORD")',
              envvar='SAML_PASSWORD')
def role_ldif(configuration_file, account_name_pattern, saml_user, saml_password):
    '''Print Role-LDIF with Template in Configuration YAML'''
    config = yaml.safe_load(configuration_file)
    accounts = config.get('accounts', {})
    global_cfg = config.get('global', {})
    saml_url = global_cfg.get('saml_identity_provider_url')
    saml_role = global_cfg.get('saml_admin_login_role')
    account_names = []
    for pattern in account_name_pattern:
        account_names.extend(sorted(fnmatch.filter(accounts.keys(), pattern)))

    if os.environ.get('AWS_PROFILE'):
        account_names.append(os.environ.get('AWS_PROFILE'))

    if not account_names:
        print('# No Account set. Try "default"..', file=sys.stderr)
        account_names.append('default')

    print('Render LDIF for following accounts: {}'.format(', '.join(account_names)), file=sys.stderr)
    for account_name in account_names:
        os.environ['AWS_PROFILE'] = account_name
        cfg = accounts.get(account_name) or {}
        for key, val in global_cfg.items():
            if key not in cfg:
                cfg[key] = val
        saml_url = cfg.get('saml_identity_provider_url')
        saml_role = cfg.get('saml_admin_login_role')

        if saml_user and saml_url and saml_role:
            account_alias = cfg.get('alias', account_name).format(account_name=account_name)
            aws_profile = 'sevenseconds-{}'.format(account_name)
            if not get_aws_credentials(saml_user, saml_password, saml_url, saml_role, account_alias, aws_profile):
                warning('Skipping account configuration of {} due to missing credentials'.format(account_name))
                continue
            os.environ['AWS_PROFILE'] = aws_profile
        print(get_role_ldif(cfg))


@cli.command()
@click.argument('account_name')
@click.argument('region')
def destroy(account_name, region):
    destroy_account(account_name, region)


def main():
    cli()
