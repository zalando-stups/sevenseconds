import click
import yaml
import socket
from sevenseconds.aws import configure_account

import sevenseconds
from sevenseconds.console import AliasedGroup, error, Action, info
import boto.cloudtrail
import boto.exception
import boto.vpc
import boto.route53
import boto.elasticache
import boto.rds2
import boto.iam


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
@click.argument('file', type=click.File('rb'))
@click.argument('region_name')
@click.argument('security_group')
def update_security_group(file, region_name, security_group):
    '''Update a Security Group and allow access from all trusted networks, NAT instances and bastion hosts'''
    config = yaml.safe_load(file)
    accounts = config.get('accounts', {})

    addresses = set()

    for name, cidr in config.get('global', {}).get('trusted_networks', {}).items():
        info('Adding trusted network {} ({})'.format(name, cidr))
        addresses.add(cidr)

    for account_name, cfg in accounts.items():
        if not cfg:
            cfg = {}
        cfg.update(config.get('global', {}))
        for region in cfg['regions']:
            domains = set(['odd-{}.{}'.format(region, cfg.get('domain').format(account_name=account_name))])
            for az in 'a', 'b', 'c':
                domains.add('nat-{}{}.{}'.format(region, az, cfg.get('domain').format(account_name=account_name)))
            for domain in sorted(domains):
                with Action('Checking {}'.format(domain)):
                    try:
                        ai = socket.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
                    except:
                        ai = []
                        pass
                    for _, _, _, _, ip_port in ai:
                        ip, _ = ip_port
                        addresses.add('{}/32'.format(ip))

    info('\n'.join(sorted(addresses)))

    conn = boto.ec2.connect_to_region(region_name)
    for sg in conn.get_all_security_groups():
        if security_group in sg.name:
            with Action('Updating security group {}..'.format(sg.name)) as act:
                for cidr in sorted(addresses):
                    try:
                        sg.authorize(ip_protocol='tcp', from_port=443, to_port=443, cidr_ip=cidr)
                    except boto.exception.EC2ResponseError as e:
                        if 'already exists' not in e.message:
                            raise
                    act.progress()


@cli.command()
@click.argument('file', type=click.File('rb'))
@click.argument('account_name')
@click.option('--dry-run', is_flag=True)
def configure(file, account_name, dry_run):
    '''Configure a single AWS account'''
    config = yaml.safe_load(file)
    accounts = config.get('accounts', {})
    if account_name not in accounts:
        error('No configuration found for account {}'.format(account_name))
        return
    cfg = accounts.get(account_name) or {}
    cfg.update(config.get('global', {}))

    configure_account(account_name, cfg, dry_run)


def main():
    cli()
