import click
import json
import requests
import time
import yaml
from netaddr import IPNetwork

import aws_account_configurator
from aws_account_configurator.console import AliasedGroup, error, Action, info
import boto.cloudtrail
import boto.vpc
import boto.route53
import boto.elasticache
import boto.rds2
import boto.iam


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

VPC_NET = IPNetwork('172.31.0.0/16')


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('AWS Account Configurator {}'.format(aws_account_configurator.__version__))
    ctx.exit()


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True)
def cli():
    pass


def find_vpc(conn):
    for vpc in conn.get_all_vpcs():
        if vpc.cidr_block == str(VPC_NET):
            return vpc


def find_subnet(subnets: list, name: str):
    for _subnet in subnets:
        if _subnet.tags.get('Name') == name:
            return _subnet


def configure_subnet(vpc_conn, vpc, az, _type: str, net: IPNetwork, subnets: list, dry_run: bool):
    name = '{}-{}'.format(_type, az.name)
    subnet = find_subnet(subnets, name)
    if not subnet:
        with Action('Creating subnet {name} with {net}..', **vars()):
            if not dry_run:
                subnet = vpc_conn.create_subnet(vpc.id, str(net), availability_zone=az.name)
                subnet.add_tags({'Name': name})


def calculate_subnet(vpc_net: IPNetwork, _type: str, az_index: int):
    '''
    >>> calculate_subnet(IPNetwork('10.0.0.0/16'), 'dmz', 0)
    IPNetwork('10.0.0.0/21')

    >>> calculate_subnet(IPNetwork('10.0.0.0/16'), 'internal', 0)
    IPNetwork('10.0.128.0/20')
    '''
    if _type == 'dmz':
        networks = list(vpc_net.subnet(21))
    else:
        # use the "upper half" of the /16 network for the internal/private subnets
        networks = list(list(vpc_net.subnet(vpc_net.prefixlen + 1))[1].subnet(20))
    return networks[az_index]


def find_trail(trails: list, name):
    for trail in trails:
        if trail.get('Name') == name:
            return trail


def filter_subnets(subnets: list, _type: str):
    for subnet in subnets:
        if subnet.tags['Name'].startswith(_type + '-'):
            yield subnet


def configure_routing(vpc_conn, ec2_conn, subnets: list, cfg: dict):
    nat_instance_by_az = {}
    for subnet in filter_subnets(subnets, 'dmz'):
        az_name = subnet.availability_zone

        sg_name = 'NAT {}'.format(az_name)
        sg = [group for group in ec2_conn.get_all_security_groups() if group.name == sg_name]
        if not sg:
            sg = ec2_conn.create_security_group(sg_name, 'Allow internet access through NAT instances',
                                                vpc_id=subnet.vpc_id)
            sg.add_tags({'Name': sg_name})

            internal_subnet = [sn for sn in filter_subnets(subnets, 'internal') if sn.availability_zone == az_name][0]
            sg.authorize(ip_protocol=-1,
                         from_port=-1,
                         to_port=-1,
                         cidr_ip=internal_subnet.cidr_block)
        else:
            sg = sg[0]

        images = ec2_conn.get_all_images(filters={'name': 'amzn-ami-vpc-nat-hvm*',
                                                  'owner_alias': 'amazon',
                                                  'root_device_type': 'ebs'})
        most_recent_image = sorted(images, key=lambda i: i.name)[-1]
        instances = ec2_conn.get_only_instances(filters={'tag:Name': sg_name, 'instance-state-name': 'running'})
        if instances:
            info('NAT instance {} is running with public IP {}'.format(sg_name, instances[0].ip_address))
            instance = instances[0]
        else:
            with Action('Launching NAT instance in {az_name}..', **vars()) as act:
                res = ec2_conn.run_instances(most_recent_image.id, subnet_id=subnet.id,
                                             instance_type=cfg.get('instance_type', 'm3.medium'),
                                             security_group_ids=[sg.id],
                                             monitoring_enabled=True,)
                instance = res.instances[0]

                status = instance.update()
                while status == 'pending':
                    time.sleep(5)
                    status = instance.update()
                    act.progress()

                if status == 'running':
                    instance.add_tag('Name', sg_name)

            with Action('Associating Elastic IP..'):
                addr = ec2_conn.allocate_address('vpc')
                addr.associate(instance.id)
            info('Elastic IP for NAT {} is {}'.format(az_name, addr.public_ip))

        with Action('Disabling source/destination checks..'):
            ec2_conn.modify_instance_attribute(instance.id, attribute='sourceDestCheck', value=False)
        nat_instance_by_az[az_name] = instance

    route_tables = vpc_conn.get_all_route_tables()
    for rt in route_tables:
        for assoc in rt.associations:
            if assoc.main:
                rt.add_tags({'Name': 'DMZ Routing Table'})
    for subnet in filter_subnets(subnets, 'internal'):
        route_table = None
        for rt in route_tables:
            if rt.tags.get('Name') == subnet.tags.get('Name'):
                route_table = rt
        instance = nat_instance_by_az[subnet.availability_zone]
        if not route_table:
            with Action('Creating route table {}..'.format(subnet.tags.get('Name'))):
                route_table = vpc_conn.create_route_table(subnet.vpc_id)
                route_table.add_tags({'Name': subnet.tags.get('Name')})
                vpc_conn.create_route(route_table.id, destination_cidr_block='0.0.0.0/0',
                                      instance_id=instance.id)

        with Action('Associating route table..'):
            vpc_conn.associate_route_table(route_table.id, subnet.id)


def configure_cloudtrail(account_name, region, cfg, dry_run):
    cloudtrail = boto.cloudtrail.connect_to_region(region)
    trails = cloudtrail.describe_trails()['trailList']
    name = 'Default'
    trail = find_trail(trails, name)
    kwargs = dict(name=name,
                  s3_bucket_name=cfg['cloudtrail']['s3_bucket_name'],
                  s3_key_prefix=cfg['cloudtrail']['s3_key_prefix'],
                  include_global_service_events=True)
    if trail:
        with Action('Updating CloudTrail..'):
            if not dry_run:
                cloudtrail.update_trail(**kwargs)
    else:
        with Action('Enabling CloudTrail..'):
            if not dry_run:
                cloudtrail.create_trail(**kwargs)


def configure_dns(account_name, cfg):
    dns_domain = cfg.get('domain').format(account_name=account_name)

    # NOTE: hardcoded region as Route53 is region-independent
    conn = boto.route53.connect_to_region('eu-west-1')
    zone = conn.get_hosted_zone_by_name(dns_domain + '.')
    if not zone:
        with Action('Creating hosted zone..'):
            conn.create_zone(dns_domain + '.', private_zone=False)
    zone = conn.get_hosted_zone_by_name(dns_domain + '.')
    zone = zone['GetHostedZoneResponse']
    nameservers = zone['DelegationSet']['NameServers']
    info('Hosted zone for {} has nameservers {}'.format(dns_domain, nameservers))
    return dns_domain


def configure_elasticache(region, subnets):
    conn = boto.elasticache.connect_to_region(region)
    subnet_ids = [sn.id for sn in filter_subnets(subnets, 'internal')]
    try:
        conn.describe_cache_subnet_groups('internal')
    except:
        with Action('Creating ElastiCache subnet group..'):
            conn.create_cache_subnet_group('internal', 'Default subnet group using all internal subnets', subnet_ids)


def configure_rds(region, subnets):
    conn = boto.rds2.connect_to_region(region)
    subnet_ids = [sn.id for sn in filter_subnets(subnets, 'internal')]
    try:
        conn.describe_db_subnet_groups('internal')
    except:
        with Action('Creating RDS subnet group..'):
            try:
                conn.create_db_subnet_group('internal', 'Default subnet group using all internal subnets', subnet_ids)
            except TypeError:
                # ignore f**cking boto error "TypeError: the JSON object must be str, not 'bytes'"
                pass


def get_account_id():
    conn = boto.iam.connect_to_region('eu-west-1')
    users = conn.get_all_users()['list_users_response']['list_users_result']['users']
    arn = [u['arn'] for u in users][0]
    account_id = arn.split(':')[4]
    return account_id


def get_account_alias():
    conn = boto.iam.connect_to_region('eu-west-1')
    resp = conn.get_account_alias()
    return resp['list_account_aliases_response']['list_account_aliases_result']['account_aliases'][0]


def configure_iam(cfg):
    # NOTE: hardcoded region as Route53 is region-independent
    conn = boto.iam.connect_to_region('eu-west-1')

    roles = cfg.get('roles', {})

    account_id = get_account_id()

    info('Account ID is {}'.format(account_id))

    for role_name, role_cfg in sorted(roles.items()):
        try:
            conn.get_role(role_name)
        except:
            with Action('Creating role {role_name}..', **vars()):
                conn.create_role(role_name, json.dumps(role_cfg.get('assume_role_policy')).format(
                                 account_id=account_id))
        with Action('Updating policy for role {role_name}..', **vars()):
            conn.put_role_policy(role_name, role_name, json.dumps(role_cfg['policy']))
        with Action('Removing invalid policies from role {role_name}..', **vars()):
            res = conn.list_role_policies(role_name)
            policy_names = res['list_role_policies_response']['list_role_policies_result']['policy_names']
            for policy_name in policy_names:
                if policy_name != role_name:
                    conn.delete_role_policy(role_name, policy_name)

    res = conn.list_saml_providers()['list_saml_providers_response']['list_saml_providers_result']
    saml_providers = res['saml_provider_list']
    for name, url in cfg.get('saml_providers', {}).items():
        arn = 'arn:aws:iam::{account_id}:saml-provider/{name}'.format(account_id=account_id, name=name)
        found = False
        for provider in saml_providers:
            if provider['arn'] == arn:
                found = True
        if found:
            info('Found existing SAML provider {name}'.format(name=name))
        else:
            with Action('Creating SAML provider {name}..', **vars()):
                r = requests.get(url)
                saml_metadata_document = r.text
                conn.create_saml_provider(saml_metadata_document, name)


def substitute_template_vars(data, context: dict):
    serialized = yaml.safe_dump(data)
    data = yaml.safe_load(serialized)
    for k, v in data.items():
        if isinstance(v, str):
            data[k] = v.format(**context)
        elif isinstance(v, dict):
            data[k] = substitute_template_vars(v, context)
    return data


def configure_bastion_host(account_name: str, dns_domain: str, ec2_conn, subnets: list, cfg: dict):
    try:
        subnet = list(filter_subnets(subnets, 'dmz'))[0]
    except:
        return

    az_name = subnet.availability_zone
    sg_name = 'SSH Bastion Host'
    sg = [group for group in ec2_conn.get_all_security_groups() if group.name == sg_name]
    if not sg:
        sg = ec2_conn.create_security_group(sg_name, 'Allow SSH access to the bastion host',
                                            vpc_id=subnet.vpc_id)
        sg.add_tags({'Name': sg_name})

        sg.authorize(ip_protocol='tcp',
                     from_port=22,
                     to_port=22,
                     cidr_ip='0.0.0.0/0')
        sg.authorize(ip_protocol='tcp',
                     from_port=2222,
                     to_port=2222,
                     cidr_ip='0.0.0.0/0')
    else:
        sg = sg[0]

        instances = ec2_conn.get_only_instances(filters={'tag:Name': sg_name, 'instance-state-name': 'running'})
        if instances:
            instance = instances[0]
            ip = instance.ip_address
        else:
            with Action('Launching SSH Bastion instance in {az_name}..', az_name=az_name) as act:
                config = substitute_template_vars(cfg.get('ami_config'), {'account_name': account_name})
                user_data = '#zalando-ami-config\n{}'.format(yaml.safe_dump(config))

                res = ec2_conn.run_instances(cfg.get('ami_id'), subnet_id=subnet.id,
                                             instance_type=cfg.get('instance_type', 't2.micro'),
                                             security_group_ids=[sg.id],
                                             user_data=user_data.encode('utf-8'),
                                             key_name=cfg.get('key_name'),
                                             monitoring_enabled=True)
                instance = res.instances[0]

                status = instance.update()
                while status == 'pending':
                    time.sleep(5)
                    status = instance.update()
                    act.progress()

                if status == 'running':
                    instance.add_tag('Name', sg_name)

            with Action('Associating Elastic IP..'):
                addr = None
                for _addr in ec2_conn.get_all_addresses():
                    if not _addr.instance_id:
                        # use existing Elastic IP (e.g. to re-use IP from previous bastion host)
                        addr = _addr
                if not addr:
                    addr = ec2_conn.allocate_address('vpc')
                addr.associate(instance.id)
            ip = addr.public_ip
        info('SSH Bastion instance is running with public IP {}'.format(ip))
        dns = 'bastion-{}.{}.'.format(az_name[:-1], dns_domain)
        dns_cname = 'bastion.{}.'.format(dns_domain)
        with Action('Adding DNS record {}'.format(dns)):
            dns_conn = boto.route53.connect_to_region('eu-west-1')
            zone = dns_conn.get_zone(dns_domain + '.')
            rr = zone.get_records()
            change = rr.add_change('UPSERT', dns, 'A')
            change.add_value(ip)
            change = rr.add_change('UPSERT', dns_cname, 'CNAME')
            change.add_value(dns)
            rr.commit()


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
    regions = cfg['regions']

    account_alias = cfg.get('alias', account_name).format(account_name=account_name)

    if account_alias != get_account_alias():
        error('Connected to "{}", but account "{}" should be configured'.format(get_account_alias(), account_alias))
        return

    for region in regions:
        configure_cloudtrail(account_name, region, cfg, dry_run)

        vpc_conn = boto.vpc.connect_to_region(region)
        ec2_conn = boto.ec2.connect_to_region(region)
        with Action('Checking region {region}..', **vars()):
            availability_zones = ec2_conn.get_all_zones()
        info('Availability zones: {}'.format(availability_zones))
        with Action('Finding VPC..'):
            vpc = find_vpc(vpc_conn)
        if not vpc:
            error('No default VPC found')
            with Action('Creating VPC for {cidr_block}..', cidr_block=str(VPC_NET)):
                if not dry_run:
                    vpc = vpc_conn.create_vpc(str(VPC_NET))
        with Action('Updating VPCe..'):
            if not dry_run:
                tags = {'Name': '{}-{}'.format(account_name, region)}
                additional_tags = cfg.get('vpc', {}).get('tags', {})
                tags.update(additional_tags)
                vpc.add_tags(tags)
        info(vpc)
        subnets = vpc_conn.get_all_subnets(filters={'vpcId': [vpc.id]})
        for subnet in subnets:
            if not subnet.tags.get('Name'):
                with Action('Deleting subnet {subnet_id}..', subnet_id=subnet.id):
                    if not dry_run:
                        vpc_conn.delete_subnet(subnet.id)
        for _type in 'dmz', 'internal':
            for i, az in enumerate(sorted(availability_zones, key=lambda az: az.name)):
                net = calculate_subnet(VPC_NET, _type, i)
                configure_subnet(vpc_conn, vpc, az, _type, net, subnets, dry_run)

        # All subnets now exist
        subnets = vpc_conn.get_all_subnets(filters={'vpcId': [vpc.id]})
        configure_routing(vpc_conn, ec2_conn, subnets, cfg.get('nat', {}))
        dns_domain = configure_dns(account_name, cfg)
        configure_bastion_host(account_name, dns_domain, ec2_conn, subnets, cfg.get('bastion', {}))
        configure_elasticache(region, subnets)
        configure_rds(region, subnets)
        configure_iam(cfg)


def main():
    cli()
