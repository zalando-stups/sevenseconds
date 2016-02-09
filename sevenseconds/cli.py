import fnmatch
import click
import yaml
import os

import sevenseconds
from clickclick import AliasedGroup
from .helper import error, info
from .helper.auth import get_sessions
from .helper.network import get_trusted_addresses
from .config import start_configuration

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


@cli.command()
@click.argument('account_name')
@click.argument('region')
def destroy(account_name, region):
    '''not yet implemented'''


@cli.command()
@click.argument('file', type=click.File('rb'))
@click.argument('account_name_pattern', nargs=-1)
@click.option('--saml-user', help='SAML username', envvar='SAML_USER', metavar='USERNAME')
@click.option('--saml-password', help='SAML password (use the environment variable "SAML_PASSWORD")',
              envvar='SAML_PASSWORD',
              metavar='PASSWORD')
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
@click.option('--login-only',
              help='exit afert Login', is_flag=True)
@click.option('--quite',
              help='log only errors', is_flag=True)
def configure(file, account_name_pattern, saml_user, saml_password, **options):
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
    if len(account_name_pattern) == 0:
        if os.environ.get('AWS_PROFILE'):
            account_name_pattern = {os.environ.get('AWS_PROFILE')}
        else:
            error('No AWS accounts given!')
            return

    for pattern in account_name_pattern:
        account_names.extend(sorted(fnmatch.filter(accounts.keys(), pattern)))

    if not account_names:
        error('No configuration found for account {}'.format(', '.join(account_name_pattern)))
        return
    sevenseconds.helper.PATTERNLENGTH = max([len(x) for x in account_names]) + 14
    sevenseconds.helper.QUITE = options.get('quite', False)

    info('Start configuration of: {}'.format(', '.join(account_names)))

    if not saml_user:
        error('SAML User still missing. Please add with --saml-user or use the ENV SAML_USER')
        return

    sessions = get_sessions(account_names, saml_user, saml_password, config, accounts, options)
    if len(sessions) == 0:
        error('No AWS accounts with login!')
        return
    if options.get('login_only'):
        return
    # Get NAT/ODD Addresses. Need the first Session to get all AZ for the Regions
    trusted_addresses = get_trusted_addresses(list(sessions.values())[0].admin_session, config)
    start_configuration(sessions, trusted_addresses, options)


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


def main():
    cli()
