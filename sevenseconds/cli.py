import re
import click
import yaml
import os
import sys

import sevenseconds
from netaddr import IPNetwork
from clickclick import AliasedGroup
from .helper import error, info, fatal_error
from .helper.auth import get_sessions
from .helper.network import get_trusted_addresses
from .helper.regioninfo import get_regions
from .config.configure import start_configuration, start_cleanup

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])
SUPPORTED_CONFIG_VERSION = 9


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('AWS Account Configurator {}'.format(sevenseconds.__version__))
    ctx.exit()


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True)
def cli():
    pass


@cli.command()
@click.argument('account_name')
@click.argument('region')
def destroy(account_name, region):
    '''not yet implemented'''


@cli.command()
@click.argument('file', type=click.File('rb'))
@click.argument('account_name_pattern')
@click.option('--dry-run', is_flag=True)
@click.option('-P', '--max-procs',
              help='Run  up  to  max-procs processes at a time. Default CPU Count',
              default=os.cpu_count(),
              type=click.INT)
@click.option('--update-odd-host', help='Update old Odd Hosts', is_flag=True)
@click.option('--redeploy-odd-host', help='Redeploy Odd Hosts (independ of age and status)', is_flag=True)
@click.option('--migrate2natgateway',
              help='Drop NAT Instance and create NAT Gateway (NETWORK OUTAGE!)',
              metavar='<REGEX>')
@click.option('--migrate2natgateway-if-empty',
              help='Drop NAT Instance and create NAT Gateway, if no other Instance running', is_flag=True)
@click.option('--re-add-defaultroute',
              help='Drop and re-add the default route of the internal subnet (NETWORK OUTAGE!)', is_flag=True)
@click.option('--login-only',
              help='exit afert Login', is_flag=True)
@click.option('--quite',
              help='log only errors', is_flag=True)
@click.option('--login-account',
              help='Log in with Account X and use AssumeRole for the other Accounts', type=click.STRING)
@click.option('--token',
              help='Oauth2 Token for AWS Credential Service', type=click.STRING)
def configure(file, account_name_pattern, **options):
    '''Configure one or more AWS account(s) matching the provided pattern

       ACCOUNT_NAME_PATTERN is a regex that is matched against the full account name

       Posible Enviroment Variables
       AWS_PROFILE     Connect to this Profile without SAML
       SSLDIR          Directory with all SSL-Files
    '''
    try:
        config, sessions = _get_session(
            'configuration of: ',
            file,
            account_name_pattern,
            options)
        session_list = list(sessions.values())
    except Exception as e:
        fatal_error("Can't get sessions. Error: {}".format(e))

    # Get NAT/ODD Addresses. Need the first Session to get all AZ for the Regions
    trusted_addresses = get_trusted_addresses(session_list[0].admin_session, config)
    run_successfully = start_configuration(session_list, trusted_addresses, options)
    if not run_successfully:
        sys.exit(1)


@cli.command('clear-region')
@click.argument('file', type=click.File('rb'))
@click.argument('region')
@click.argument('account_name_pattern')
@click.option('--dry-run', is_flag=True)
@click.option('-P', '--max-procs',
              help='Run  up  to  max-procs processes at a time. Default CPU Count',
              default=os.cpu_count(),
              type=click.INT)
@click.option('--quite',
              help='log only errors', is_flag=True)
@click.option('--login-account',
              help='Log in with Account X and use AssumeRole for the other Accounts', type=click.STRING)
@click.option('--token',
              help='Oauth2 Token for AWS Credential Service', type=click.STRING)
def clear_region(file, region, account_name_pattern, **options):
    '''drop all stups service from region X

       ACCOUNT_NAME_PATTERN are Unix shell style:

       \b
         *       matches everything
         ?       matches any single character
         [seq]   matches any character in seq
         [!seq]  matches any char not in seq

        Posible Enviroment Variables
        AWS_PROFILE     Connect to this Profile without SAML
    '''
    try:
        config, sessions = _get_session(
            'cleanup of region {} in '.format(region),
            file,
            account_name_pattern,
            options)
    except Exception as e:
        fatal_error("Can't get sessions. Error: {}".format(e))

    start_cleanup(region, sessions, options)


@cli.command('update-security-group')
@click.argument('file', type=click.File('rb'))
@click.argument('region')
@click.argument('account_name_pattern')
@click.argument('security_group', nargs=-1)
def cli_update_security_group(file, region, account_name_pattern, security_group):
    '''Update a Security Group and allow access from all trusted networks, NAT instances and bastion hosts'''
    try:
        config, sessions = _get_session(
            'update Secuity Group in region {} for '.format(region),
            file,
            [account_name_pattern])
    except Exception as e:
        fatal_error("Can't get sessions. Error: {}".format(e))
    addresses = get_trusted_addresses(list(sessions.values())[0].admin_session, config)
    info(', '.join(sorted(addresses)))
    fatal_error('not implemented yet')


def load_config(file):
    result = yaml.safe_load(file)
    config_version = result.get('version')
    if config_version != SUPPORTED_CONFIG_VERSION:
        error = "Only configuration version {} is supported (found {}), please update sevenseconds".format(
            SUPPORTED_CONFIG_VERSION, config_version)
        raise Exception(error)
    return result


@cli.command('verify-trusted-networks')
@click.argument('file', type=click.File('rb'))
@click.argument('cidr-list', nargs=-1)
def verify_trusted_networks(file, cidr_list):
    '''Check if the given CIDR included in the trusted networks list

    CIDR        One or more CIDR Network Blocks'''
    config = load_config(file)
    addresses = set()
    for name, net in config.get('global', {}).get('trusted_networks', {}).items():
        addresses.add(IPNetwork(net))
    found = []
    not_found = []
    for net in cidr_list:
        cidr = IPNetwork(net)
        overlaps = False
        for trusted in addresses:
            if cidr in trusted:
                overlaps = True
                break
        if overlaps:
            found.append(cidr)
        else:
            not_found.append(cidr)
    if len(not_found):
        print('Not mached:\n{}'.format('\n'.join([str(x) for x in sorted(set(not_found))])))
    elif len(found) > 0 and len(not_found) == 0:
        print('All Networks are matched!')


def _get_session(msg, file, account_name_pattern, options):
    config = load_config(file)
    accounts = config.get('accounts', {})

    account_names = [account for account in accounts.keys() if re.fullmatch(account_name_pattern, account)]

    if not account_names:
        error('No configuration found for account {}'.format(account_name_pattern))
        raise

    account_name_length = max([len(x) for x in account_names])
    region_name_length = max([len(x) for x in get_regions('cloudtrail')])
    sevenseconds.helper.PATTERNLENGTH = account_name_length + region_name_length + 2
    sevenseconds.helper.QUITE = options.get('quite', False)

    info('Start {}{}'.format(msg, ', '.join(account_names)))

    sessions = get_sessions(account_names, config, accounts, options)
    if len(sessions) == 0:
        error('No AWS accounts with login!')
        raise
    if options.get('login_only'):
        raise
    return config, sessions


def main():
    cli()
