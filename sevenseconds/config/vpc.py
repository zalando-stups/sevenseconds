import time
import json
import re
import hashlib
from collections import namedtuple
from netaddr import IPNetwork
from ..helper import ActionOnExit, info, warning, error
from ..helper.network import calculate_subnet
from ..helper.aws import filter_subnets, get_tag, get_az_names, associate_address
from .route53 import configure_dns_record, delete_dns_record
from clickclick import OutputFormat
from clickclick.console import print_table
from ..config import AccountData

VPC_NET = IPNetwork('172.31.0.0/16')
Subnet = namedtuple('Subnet', ['availability_zone', 'subnet_type', 'cidr', 'tags'])


def configure_vpc(account: AccountData, region, base_ami_id):
    ec2 = account.session.resource('ec2', region)
    ec2c = account.session.client('ec2', region)

    vpc_net = VPC_NET

    vpc_config = account.config.get('vpc_net', {}).get(region)
    if vpc_config:
        vpc_net = IPNetwork(account.config['vpc_net'][region]['cidr'])
        info('Region with non default VPC-Network: {}'.format(vpc_net))
        with ActionOnExit('Finding existing default VPC..'):
            vpc = find_vpc(ec2, VPC_NET)
        if vpc:
            with ActionOnExit('Deleting old default VPC..') as act:
                delete_vpc(vpc, region)
                delete_vpc_addresses(account.session, region)
                delete_rds_subnet_group(account.session, region)
                try:
                    vpc.delete()
                except Exception as e:
                    act.error(e)
                    raise Exception('{}! Please delete VPC ({}) manually.'.format(e, vpc.id))

    with ActionOnExit('Finding VPC..') as act:
        vpc = find_vpc(ec2, vpc_net)
        if not vpc:
            act.error('VPC not found')
    if not vpc:
        with ActionOnExit('Creating VPC for {cidr_block}..', cidr_block=str(vpc_net)):
            if not account.dry_run:
                vpc = ec2.create_vpc(CidrBlock=str(vpc_net))
                igw = ec2.create_internet_gateway()
                vpc.attach_internet_gateway(InternetGatewayId=igw.id)
    with ActionOnExit('Updating VPC..'):
        if not account.dry_run:
            tags = [{'Key': 'Name', 'Value': '{}-{}'.format(account.name, region)},
                    {'Key': 'LastUpdate', 'Value': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
                    ]
            for key, val in account.config.get('vpc', {}).get('tags', {}).items():
                tags.append({
                    'Key': key,
                    'Value': val.replace('{{ami_id}}', base_ami_id).replace(
                        '{{base_ami_config}}',
                        json.dumps(account.config.get('base_ami'), sort_keys=True))
                })
            vpc.create_tags(Tags=tags)
            vpc.modify_attribute(EnableDnsSupport={'Value': True})
            vpc.modify_attribute(EnableDnsHostnames={'Value': True})
    info(vpc)
    # FIXME check and add Expire for Flow Logs
    with ActionOnExit('Check Flow Logs') as act:
        if not exist_flowlog(account.session, region, vpc.id):
            ec2c.create_flow_logs(ResourceIds=[vpc.id],
                                  ResourceType='VPC',
                                  TrafficType='ALL',
                                  LogGroupName='vpc-flowgroup',
                                  DeliverLogsPermissionArn='arn:aws:iam::{}:role/vpc-flowlogs'.format(account.id))

    with ActionOnExit('Checking region {region}..', **vars()):
        availability_zones = get_az_names(account.session, region)
    info('Availability zones: {}'.format(availability_zones))
    for subnet in vpc.subnets.all():
        if not get_tag(subnet.tags, 'Name'):
            with ActionOnExit('Deleting subnet {subnet_id}..', subnet_id=subnet.id):
                if not account.dry_run:
                    subnet.delete()

    # Configure subnets
    if vpc_config and 'subnets' in vpc_config:
        subnets = custom_subnets(vpc_net, vpc_config['subnets'], availability_zones)
    else:
        subnets = default_subnets(vpc_net, availability_zones)

    for subnet in subnets:
        configure_subnet(vpc, subnet, account.dry_run, ec2c.get_waiter('subnet_available'))

    enable_nat = account.config.get("enable_nat", True)
    if enable_nat:
        nat_instances = create_nat_instances(account, vpc, region)
    else:
        nat_instances = {}

    create_routing_tables(
        vpc, nat_instances,
        account.options.get('re_add_defaultroute', False),
        account.config.get('enable_dedicated_dmz_route', False)
    )
    create_vpc_endpoints(account, vpc, region)
    check_vpn_propagation(account, vpc, region)
    return vpc


def custom_subnets(vpc_net, subnet_config, availability_zones):
    for az in sorted(availability_zones):
        for subnet in subnet_config[az]:
            cidr = IPNetwork(subnet['cidr'])
            if cidr not in vpc_net:
                raise Exception("Subnet {} doesn't belong to VPC {}".format(subnet, vpc_net))
            yield Subnet(az, subnet['type'], cidr, subnet.get('tags', {}))


def default_subnets(vpc_net, availability_zones):
    for subnet_type in 'dmz', 'internal':
        for i, az in enumerate(sorted(availability_zones)):
            tags = {}
            if subnet_type == 'dmz':
                tags['kubernetes.io/role/elb'] = ''
                tags['kubernetes.io/role/internal-elb'] = ''
            yield Subnet(az, subnet_type, calculate_subnet(vpc_net, subnet_type, i), tags)


def exist_flowlog(session, region, vpc_id):
    client = session.client('ec2', region)
    for flowlog in client.describe_flow_logs()['FlowLogs']:
        if (flowlog['LogGroupName'] == 'vpc-flowgroup' and
                flowlog['ResourceId'] == vpc_id):
            return True
    return False


def find_vpc(ec2: object, vpc_net: IPNetwork):
    for vpc in ec2.vpcs.all():
        if vpc.cidr_block == str(vpc_net):
            return vpc


def delete_vpc(vpc: object, region: str):
    '''
    Delete only, if the VPC use only for NAT and ODD instances
    '''
    instances2delete = []
    instances2clarify = []
    for instance in vpc.instances.all():
        if (get_tag(instance.tags, 'Name', str).startswith('NAT {}'.format(region)) or
                get_tag(instance.tags, 'Name') == 'Odd (SSH Bastion Host)'):
            instances2delete.append(instance)
        else:
            instances2clarify.append(instance)

    if instances2clarify:
        raise Exception('Unknown Instances ({}) found. Please clear VPC ({}) manually.'
                        .format(', '.join(map(lambda x: '{}/{}: {}'.format(x.id, get_tag(x.tags, 'Name'), x.state),
                                              instances2clarify)), vpc.id))

    if instances2delete:
        for instance in instances2delete:
            info('terminate {}/{}'.format(instance.id, get_tag(instance.tags, 'Name')))
            instance.modify_attribute(Attribute='disableApiTermination', Value='false')
            instance.terminate()

        for instance in instances2delete:
            instance.wait_until_terminated()
            instance.reload()
            info('instance status from {}/{}: {}'.format(instance.id, get_tag(instance.tags, 'Name'), instance.state))

    network_interfaces = list(vpc.network_interfaces.all())
    if network_interfaces:
        raise Exception('Unknown Interfaces ({}) found. Please clear VPC ({}) manually.'
                        .format(', '.join(map(lambda x: '{}/{}: {}'.format(x.id, x.description, x.status),
                                              network_interfaces)), vpc.id))

    for igw in vpc.internet_gateways.all():
        igw.detach_from_vpc(VpcId=vpc.id)
        igw.delete()

    for subnet in vpc.subnets.all():
        try:
            subnet.delete()
        except Exception as e:
            info(e)

    for sg in vpc.security_groups.all():
        try:
            sg.delete()
        except Exception as e:
            info(e)

    for network_acl in vpc.network_acls.all():
        try:
            network_acl.delete()
        except Exception as e:
            info(e)

    endpoints = vpc.meta.client.describe_vpc_endpoints(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values': [
                    vpc.id
                ]
            },
            {
                'Name': 'vpc-endpoint-state',
                'Values': [
                    'pending',
                    'available'
                ]
            }
        ]
    )['VpcEndpoints']
    if endpoints:
        for endpoint in endpoints:
            vpc.meta.client.delete_vpc_endpoints(
                VpcEndpointIds=[endpoint['VpcEndpointId']]
            )

    for route_table in vpc.route_tables.all():
        try:
            route_table.delete()
        except Exception as e:
            info(e)

    # TODO missing?
    # VPN Attachments
    # VPC Peering Connections


def delete_vpc_addresses(session: object, region: str):
    ec2 = session.resource('ec2', region)
    for vpc_address in ec2.vpc_addresses.all():
        if vpc_address.association_id is None:
            try:
                vpc_address.release()
            except Exception as e:
                info(e)


def delete_rds_subnet_group(session: object, region: str):
    rds = session.client('rds', region)
    for name in ['internal', 'default']:
        try:
            rds.delete_db_subnet_group(DBSubnetGroupName=name)
        except Exception as e:
            info(e)


def configure_subnet(vpc, subnet: Subnet, dry_run: bool, waiter):
    name = '{}-{}'.format(subnet.subnet_type, subnet.availability_zone)
    tags = dict(subnet.tags)
    tags['Name'] = name
    existing_subnet = find_subnet(vpc, subnet.cidr)
    if not existing_subnet:
        with ActionOnExit('Creating subnet {name} with {cidr}..', name=name, cidr=subnet.cidr):
            if not dry_run:
                existing_subnet = vpc.create_subnet(CidrBlock=str(subnet.cidr),
                                                    AvailabilityZone=subnet.availability_zone)
                waiter.wait(SubnetIds=[existing_subnet.id], Filters=[
                    {'Name': 'cidrBlock',
                     'Values': [str(subnet.cidr)]},
                    {'Name': 'availabilityZone',
                     'Values': [subnet.availability_zone]}
                ])
    existing_subnet.create_tags(Tags=[{'Key': k, 'Value': v} for k, v in tags.items()])


def find_subnet(vpc: object, cidr):
    for subnet in vpc.subnets.all():
        if subnet.cidr_block == str(cidr):
            return subnet


def create_nat_instances(account: AccountData, vpc: object, region: str):
    ec2 = account.session.resource('ec2', region)
    ec2c = account.session.client('ec2', region)
    logs = account.session.client('logs', region)
    nat_instance_by_az = {}
    nat_type = None
    for subnet in filter_subnets(vpc, 'dmz'):
        az_name = subnet.availability_zone
        private_ip = None
        sg_name = 'NAT {}'.format(az_name)
        # GroupNames-Filter: EC2-Classic and default VPC only
        sg = [x for x in vpc.security_groups.all() if x.group_name == sg_name]
        if not sg:
            sg = vpc.create_security_group(GroupName=sg_name,
                                           Description='Allow internet access through NAT instances')
            # We are to fast for AWS (InvalidGroup.NotFound)
            time.sleep(2)
            sg.create_tags(Tags=[{'Key': 'Name', 'Value': sg_name}])

            for internal_subnet in filter_subnets(vpc, 'internal'):
                if internal_subnet.availability_zone == az_name:
                    sg.authorize_ingress(IpProtocol='-1',
                                         FromPort=-1,
                                         ToPort=-1,
                                         CidrIp=internal_subnet.cidr_block)
        else:
            sg = sg[0]

        filters = [
            {'Name': 'tag:Name',
             'Values': [sg_name]},
            {'Name': 'instance-state-name',
             'Values': ['running', 'pending', 'stopping', 'stopped', 'shutting-down']},
        ]
        instances = list(subnet.instances.filter(Filters=filters))
        nat_gateway = None
        try:
            filters = [
                {'Name': 'subnet-id', 'Values': [subnet.id]},
                {'Name': 'state', 'Values': ['pending', 'available', 'deleting']}
            ]
            nat_gateway = ec2c.describe_nat_gateways(Filter=filters)['NatGateways']
            support_nat_gateway = True
        except Exception:
            support_nat_gateway = False
        while len(nat_gateway) and nat_gateway[0]['State'] == 'deleting':
            warning('Nat Gateway in {} is deleting.. waiting..'.format(az_name))
            time.sleep(10)
            nat_gateway = ec2c.describe_nat_gateways(Filter=filters)['NatGateways']
        if nat_gateway:
            nat_instance_by_az[az_name] = {'NatGatewayId': nat_gateway[0]['NatGatewayId']}
            nat_type = 'gateway'
            while nat_gateway[0]['State'] == 'pending':
                warning('Nat Gateway in {} is pending.. waiting..'.format(az_name))
                time.sleep(10)
                nat_gateway = ec2c.describe_nat_gateways(Filter=filters)['NatGateways']
            ip = nat_gateway[0]['NatGatewayAddresses'][0].get('PublicIp')
            private_ip = nat_gateway[0]['NatGatewayAddresses'][0].get('PrivateIp')
            network_interface_id = nat_gateway[0]['NatGatewayAddresses'][0].get('NetworkInterfaceId')
        elif instances:
            instance = instances[0]
            nat_instance_by_az[az_name] = {'InstanceId': instance.id}
            nat_type = 'instance'
            ip = instance.public_ip_address
            private_ip = instance.private_ip_address
            network_interface_id = instance.network_interfaces[0].id
            if ip is None:
                with ActionOnExit('Associating Elastic IP..'):
                    ip = associate_address(ec2c, instance.id)

            with ActionOnExit('Disabling source/destination checks..'):
                instance.modify_attribute(SourceDestCheck={'Value': False})

            if support_nat_gateway:
                instance_count = 0
                all_instance_filters = [
                    {'Name': 'availability-zone',
                     'Values': [az_name]},
                    {'Name': 'instance-state-name',
                     'Values': ['running', 'pending', 'stopping', 'stopped', 'shutting-down']},
                ]
                for inst in ec2.instances.filter(Filters=all_instance_filters):
                    if get_tag(inst.tags, 'Name') != sg_name and get_tag(inst.tags, 'Name') != 'Odd (SSH Bastion Host)':
                        instance_count += 1
                pattern = account.options.get('migrate2natgateway')
                if isinstance(pattern, str):
                    if re.fullmatch(pattern, az_name) or re.fullmatch(pattern, region):
                        terminitate_nat_instance(instance, az_name)
                        instances = None
                        instance = None
                elif instance.state.get('Name') in ('stopping', 'stopped', 'shutting-down'):
                    warning('NAT Instance ({} in {}) are down. Terminate for Migration...'.format(instance.id, az_name))
                    terminitate_nat_instance(instance, az_name)
                    instances = None
                    instance = None
                elif account.options.get('migrate2natgateway_if_empty'):
                    if instance_count == 0:
                        terminitate_nat_instance(instance, az_name)
                        instances = None
                        instance = None
                    else:
                        warning('Skip migration from NAT Instance to NAT Gateway in {} (Instance Count: {})'.format(
                            az_name,
                            instance_count))
                elif instance_count == 0:
                    warning('Skip migration from NAT Instance to NAT Gateway in {} (Instance Count: {})'.format(
                        az_name,
                        instance_count))

        if not nat_gateway and not instances:
            if support_nat_gateway:
                with ActionOnExit('Launching NAT Gateway in {az_name}..', **vars()):
                    # create new Nat Gateway if no legacy Nat running
                    allocation_id, ip = associate_address(ec2c)
                    response = ec2c.create_nat_gateway(
                        SubnetId=subnet.id,
                        AllocationId=allocation_id,
                        ClientToken='{}-{}'.format(sg_name, subnet.id)
                    )
                    info(response)
                    nat_instance_by_az[az_name] = {'NatGatewayId': response['NatGateway']['NatGatewayId']}
                    nat_type = 'gateway'
            else:
                with ActionOnExit('Launching NAT instance in {az_name}..', **vars()):
                    filters = [
                        {'Name': 'name',
                         'Values': ['amzn-ami-vpc-nat-hvm*']},
                        {'Name': 'owner-alias',
                         'Values': ['amazon']},
                        {'Name': 'state',
                         'Values': ['available']},
                        {'Name': 'root-device-type',
                         'Values': ['ebs']}
                    ]
                    images = sorted(ec2.images.filter(Filters=filters), key=lambda x: x.creation_date, reverse=True)
                    most_recent_image = images[0]
                    instance = subnet.create_instances(ImageId=most_recent_image.id,
                                                       InstanceType=account.config.get('instance_type', 'm3.medium'),
                                                       SecurityGroupIds=[sg.id],
                                                       MinCount=1,
                                                       MaxCount=1,
                                                       DisableApiTermination=True,
                                                       Monitoring={'Enabled': True})[0]

                    waiter = ec2c.get_waiter('instance_running')
                    waiter.wait(InstanceIds=[instance.id])
                    instance.create_tags(Tags=[{'Key': 'Name', 'Value': sg_name}])
                    ip = None
                    # FIXME activate Autorecovery !!

                if ip is None:
                    with ActionOnExit('Associating Elastic IP..'):
                        ip = associate_address(ec2c, instance.id)

                with ActionOnExit('Disabling source/destination checks..'):
                    instance.modify_attribute(SourceDestCheck={'Value': False})
                nat_instance_by_az[az_name] = {'InstanceId': instance.id}
                nat_type = 'instance'

        if ip is not None and private_ip is not None and network_interface_id is not None:
            for direction in ('IN', 'OUT'):
                for filter_type in ('packets', 'bytes'):
                    filter_name = 'NAT-{}-{}-{}'.format(az_name, direction, filter_type)
                    with ActionOnExit('put metric filter for {}..'.format(filter_name)) as act:
                        filter_pattern = '[version, accountid, interfaceid={}, '.format(network_interface_id)
                        local_net_pattern = '.'.join(private_ip.split('.')[:1])
                        if direction == 'IN':
                            filter_pattern += 'srcaddr!={}.*, dstaddr={}, '.format(local_net_pattern, private_ip)
                        else:
                            filter_pattern += 'dstaddr={}, srcaddr!={}.*, '.format(private_ip, local_net_pattern)
                        filter_pattern += 'srcport, dstport, protocol, packets, bytes, start, end, action, log_status]'
                        response = logs.put_metric_filter(
                            logGroupName='vpc-flowgroup',
                            filterName=filter_name,
                            filterPattern=filter_pattern,
                            metricTransformations=[
                                {
                                    'metricName': filter_name,
                                    'metricNamespace': 'NAT',
                                    'metricValue': '${}'.format(filter_type)
                                },
                            ]
                        )
                        if (not isinstance(response, dict) or
                                response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200):
                            act.error(response)

        info('NAT {} {} is running with Elastic IP {} ({})'.format(nat_type,
                                                                   az_name,
                                                                   ip,
                                                                   nat_instance_by_az[az_name]))

        if account.domain is not None:
            configure_dns_record(account, 'nat-{}'.format(az_name), ip)
        else:
            warning('No DNS domain configured, skipping record creation')

    filters = [
        {'Name': 'state', 'Values': ['pending']}
    ]
    pending_nat_gateway = ec2c.describe_nat_gateways(Filter=filters)['NatGateways']
    if len(pending_nat_gateway):
        with ActionOnExit('Waiting of pending NAT Gateways..'):
            while len(ec2c.describe_nat_gateways(Filter=filters)['NatGateways']):
                time.sleep(15)

    return nat_instance_by_az


def terminitate_nat_instance(instance, az_name):
    with ActionOnExit('Terminating NAT Instance for migration in {}..'.format(az_name)):
        instance.modify_attribute(Attribute='disableApiTermination', Value='false')
        instance.terminate()
        instance.wait_until_terminated()


def create_routing_tables(vpc: object, nat_instance_by_az: dict,
                          replace_default_route: bool, enable_dedicated_dmz_route: bool):
    for route_table in vpc.route_tables.all():
        for association in route_table.associations:
            if association.main:
                for igw in vpc.internet_gateways.all():
                    route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                             GatewayId=igw.id)
                # FIXME: Can we change the name of the default routing table?
                route_table.create_tags(
                    Tags=[{'Key': 'Name', 'Value': 'DMZ Routing Table'}])

    configure_routing_table(vpc, nat_instance_by_az,
                            replace_default_route, 'internal', False)
    if enable_dedicated_dmz_route:
        configure_routing_table(vpc, nat_instance_by_az,
                                replace_default_route, 'dmz', True)


def configure_routing_table(vpc: object, nat_instance_by_az: dict, replace_default_route: bool,
                            filter_name: str, route_via_igw: bool):
    for subnet in filter_subnets(vpc, filter_name):
        route_table = None
        for rt in vpc.route_tables.all():
            if get_tag(rt.tags, 'Name', 'undef-rt-name') == get_tag(subnet.tags, 'Name', 'undef-subnet-name'):
                route_table = rt
                break
        destination = None
        if route_via_igw:
            for igw in vpc.internet_gateways.all():
                destination = {'GatewayId': igw.id}
        else:
            destination = nat_instance_by_az.get(subnet.availability_zone)
        if destination is None:
            warning('Skip routing table for {} (no destination)')
            continue
        if not route_table:
            with ActionOnExit('Creating route table {}..'.format(get_tag(subnet.tags, 'Name'))):
                route_table = vpc.create_route_table()
                route_table.create_tags(Tags=[{'Key': 'Name', 'Value': get_tag(subnet.tags, 'Name')}])
                route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                         **destination)

        with ActionOnExit('Checking route table..') as act:
            found_default_route = False
            for route in route_table.routes:
                if route.destination_cidr_block == '0.0.0.0/0':
                    if route.state == 'blackhole' or replace_default_route:
                        act.warning('delete old default destination')
                        vpc.meta.client.delete_route(RouteTableId=route_table.id,
                                                     DestinationCidrBlock='0.0.0.0/0')
                    else:
                        found_default_route = True
            if not found_default_route:
                act.warning('add new default destination')
                route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                         **destination)
        with ActionOnExit('Associating route table..'):
            route_table.associate_with_subnet(SubnetId=subnet.id)
            route_table.create_tags(Tags=[
                {
                    'Key': 'AvailabilityZone',
                    'Value': subnet.availability_zone
                },
                {
                    'Key': 'Type',
                    'Value': filter_name
                }
            ])


def create_vpc_endpoints(account: AccountData, vpc: object, region: str):
    ec2c = account.session.client('ec2', region)
    service_names = ec2c.describe_vpc_endpoint_services()['ServiceNames']

    for service_name in service_names:
        if service_name.endswith('.s3') or service_name.endswith('.dynamodb'):
            create_gtw_vpc_endpoint(service_name, vpc, ec2c, region)
        elif service_name.endswith('.kms'):
            create_interface_vpc_endpoint(service_name, vpc, ec2c, region)
        else:
            info('found new possible service endpoint: {}'.format(service_name))


def create_gtw_vpc_endpoint(service_name: str, vpc: object, ec2c: object, region: str):
    router_tables = set([rt.id for rt in vpc.route_tables.all()])
    with ActionOnExit('Checking VPC Endpoint {}..'.format(service_name)) as act:
        endpoints = ec2c.describe_vpc_endpoints(
            Filters=[
                {
                    'Name': 'service-name',
                    'Values': [
                        service_name
                    ]
                },
                {
                    'Name': 'vpc-id',
                    'Values': [
                        vpc.id
                    ]
                },
                {
                    'Name': 'vpc-endpoint-state',
                    'Values': [
                        'pending',
                        'available'
                    ]
                }
            ]
        )['VpcEndpoints']
        if endpoints:
            for endpoint in endpoints:
                rt_in_endpoint = set(endpoint['RouteTableIds'])
                if rt_in_endpoint != router_tables:
                    options = {'VpcEndpointId': endpoint['VpcEndpointId']}
                    if rt_in_endpoint.difference(router_tables):
                        options['RemoveRouteTableIds'] = list(rt_in_endpoint.difference(router_tables))
                    if router_tables.difference(rt_in_endpoint):
                        options['AddRouteTableIds'] = list(router_tables.difference(rt_in_endpoint))
                    response = ec2c.modify_vpc_endpoint(**options)
                    act.warning('mismatch ({} vs. {}), make update: {}'.format(
                        rt_in_endpoint,
                        router_tables,
                        response,
                    ))
        else:
            options = {
                'VpcId': vpc.id,
                'ServiceName': service_name,
                'RouteTableIds': list(router_tables),
                'ClientToken': hashlib.md5(
                    '{}-{}-{}:{}'.format(
                        service_name,
                        region,
                        vpc.id,
                        sorted(list(router_tables))
                    ).encode('utf-8')).hexdigest()
            }
            response = ec2c.create_vpc_endpoint(**options)
            act.warning('missing, make create: {}'.format(response))


def create_interface_vpc_endpoint(service_name: str, vpc: object, ec2c: object, region: str):
    subnets = set([subnet.id for subnet in filter_subnets(vpc, "internal")])
    with ActionOnExit('Checking VPC Endpoint {}..'.format(service_name)) as act:
        sg_name = 'KMS VPC Endpoint'
        sg_desc = 'Allow access to the KMS VPC endpoint'
        sg = get_sg(sg_name, sg_desc, vpc.security_groups.all())
        if not sg:
            sg = vpc.create_security_group(
                GroupName=sg_name,
                Description=sg_desc,
            )
            time.sleep(2)
            sg.create_tags(
                Tags=[
                    {'Key': 'Name', 'Value': sg_name},
                    {'Key': 'InfrastructureComponent', 'Value': 'true'}
                ])
            act.warning('missing, make create: {}'.format(sg))
        if not allow_https_vpc_cidr(sg.ip_permissions, vpc.cidr_block):
            act.warning(
                'missing HTTP permission, make authorize: {} port=443 CIDR={}'.format(
                    sg,
                    vpc.cidr_block,
                )
            )
            sg.authorize_ingress(
                IpProtocol='tcp',
                FromPort=443,
                ToPort=443,
                CidrIp=vpc.cidr_block,
            )
        endpoints = ec2c.describe_vpc_endpoints(
            Filters=[
                {'Name': 'service-name', 'Values': [service_name]},
                {'Name': 'vpc-id', 'Values': [vpc.id]},
                {'Name': 'vpc-endpoint-state', 'Values': ['pending', 'available']},
            ]
        )['VpcEndpoints']
        if endpoints:
            for endpoint in endpoints:
                sgs_in_endpoint = [group['GroupId'] for group in endpoint['Groups']]
                if sg.id not in sgs_in_endpoint:
                    options = {
                        'VpcEndpointId': endpoint['VpcEndpointId'],
                        'AddSecurityGroupIds': [sg.id],
                    }
                    response = ec2c.modify_vpc_endpoint(**options)
                    act.warning(
                        'mismatch ({} not in {}), make update: {}'.format(
                            sg.id,
                            sgs_in_endpoint,
                            response,
                        )
                    )
                if not endpoint['PrivateDnsEnabled']:
                    options = {
                        'VpcEndpointId': endpoint['VpcEndpointId'],
                        'PrivateDnsEnabled': True,
                    }
                    response = ec2c.modify_vpc_endpoint(**options)
                    act.warning(
                        'mismatch (PrivateDns not enabled), make update: {}'.format(response)
                    )
                subnet_in_endpoint = set(endpoint['SubnetIds'])
                if subnet_in_endpoint != subnets:
                    options = {'VpcEndpointId': endpoint['VpcEndpointId']}
                    if subnet_in_endpoint.difference(subnets):
                        options['RemoveSubnetIds'] = list(
                            subnet_in_endpoint.difference(subnets)
                        )
                    if subnets.difference(subnet_in_endpoint):
                        options['AddSubnetIds'] = list(
                            subnets.difference(subnet_in_endpoint)
                        )
                    response = ec2c.modify_vpc_endpoint(**options)
                    act.warning(
                        'mismatch ({} vs. {}), make update: {}'.format(
                            subnet_in_endpoint,
                            subnets,
                            response,
                        )
                    )
        else:
            options = {
                'VpcEndpointType': 'Interface',
                'VpcId': vpc.id,
                'ServiceName': service_name,
                'SubnetIds': list(subnets),
                'SecurityGroupIds': [sg.id],
                'PrivateDnsEnabled': True,
                'ClientToken': hashlib.md5(
                    '{}-{}-{}:{}'.format(
                        service_name, region, vpc.id, sorted(list(subnets))
                    ).encode('utf-8')
                ).hexdigest(),
            }
            response = ec2c.create_vpc_endpoint(**options)
            act.warning(
                'missing, make create: {}'.format(response)
            )


def check_vpn_propagation(account: AccountData, vpc: object, region: str):
    ec2c = account.session.client('ec2', region)
    for vpn_gateway in ec2c.describe_vpn_gateways(Filters=[
        {
            'Name': 'attachment.vpc-id',
            'Values': [
                vpc.id,
            ]
        },
    ]).get('VpnGateways', []):
        for route_table in vpc.route_tables.all():
            msg = '{} | {} Route Propagation {} | {}: '.format(
                route_table.id,
                get_tag(route_table.tags, 'Name'),
                vpn_gateway['VpnGatewayId'],
                get_tag(vpn_gateway.get('Tags', {}), 'Name'))
            if is_vgw_propagation_active(route_table.propagating_vgws, vpn_gateway['VpnGatewayId']):
                info('{} {}'.format(msg, 'Yes'))
            else:
                error('{} {}'.format(msg, 'No'))


def is_vgw_propagation_active(propagating_vgws: list, vgw_id: str):
    for propagated_vgw in propagating_vgws:
        if propagated_vgw.get('GatewayId', 'none') == vgw_id:
            return True
    return False


def if_vpc_empty(account: AccountData, region: str):
    ec2 = account.session.resource('ec2', region)
    ec2c = account.session.client('ec2', region)

    def instance_state(instance_id):
        if instance_id:
            return ec2.Instance(id=instance_id).state.get('Name')

    def if_stups_tool(ni: dict):
        instance_id = ni.get('Attachment', {}).get('InstanceId')
        if instance_id:
            instance = ec2.Instance(id=instance_id)
            availability_zones = get_az_names(account.session, region)
            stups_names = ('Odd (SSH Bastion Host)',) + tuple(['NAT {}'.format(x) for x in availability_zones])
            if get_tag(instance.tags, 'Name') in stups_names:
                return True
            if get_tag(instance.tags, 'aws:cloudformation:logical-id') == 'OddServerInstance':
                return True
        allocation_id = ni.get('Association', {}).get('AllocationId')
        if allocation_id:
            for gateway in ec2c.describe_nat_gateways()['NatGateways']:
                if gateway.get('NatGatewayAddresses', {})[0].get('AllocationId') == allocation_id:
                    return True

        # use the SecurityGroup name on the ENI to determine if it's one belonging to the KMS VPC endpoint.
        sg_name = ','.join([group["GroupName"] for group in ni.get("Groups")])
        if sg_name == "KMS VPC Endpoint":
            return True
        return False

    account_is_free = True
    rows = []
    for ni in ec2c.describe_network_interfaces()['NetworkInterfaces']:
        can_remove = if_stups_tool(ni)
        if not can_remove:
            account_is_free = False
        # print(' '.join([str(ni), str(ni.groups), str(ni.attachment), ni.description]))
        rows.append({'network_id': ni.get('NetworkInterfaceId'),
                     'group_name': ', '.join([group['GroupName'] for group in ni.get('Groups')]),
                     'description': ni.get('Description'),
                     'status': ni.get('Attachment', {}).get('Status'),
                     'instance_owner_id': ni.get('Attachment', {}).get('InstanceOwnerId'),
                     'instance_id': ni.get('Attachment', {}).get('InstanceId', ''),
                     'state': instance_state(ni.get('Attachment', {}).get('InstanceId')),
                     'allocation_id': ni.get('Association', {}).get('AllocationId'),
                     'account_name': account.name,
                     'can_remove': '✔' if can_remove else '✘'

                     })
    rows.sort(key=lambda x: (x['account_name'], x['group_name'], x['instance_id']))
    with OutputFormat('text'):
        print_table('''
                    can_remove
                    account_name
                    network_id
                    allocation_id
                    description
                    group_name
                    status
                    instance_owner_id
                    instance_id state
                    '''.split(),
                    rows,
                    styles={
                        'running': {'fg': 'green'},
                        'stopped': {'fg': 'red', 'bold': True},
                        '✔': {'bg': 'green'},
                        '✘': {'bg': 'red', 'bold': True},
                    })

    return account_is_free


def delete_nat_host(account: AccountData, region: str):
    ec2 = account.session.resource('ec2', region)
    availability_zones = get_az_names(account.session, region)
    for instance in ec2.instances.all():
        if instance.state.get('Name') in ('running', 'pending', 'stopping', 'stopped'):
            if account.domain is not None and instance.public_ip_address:
                delete_dns_record(account,
                                  'nat-{}'.format(instance.subnet.availability_zone),
                                  instance.public_ip_address)
            # Drop Bastion and NAT Instances
            stups_names = tuple(['NAT {}'.format(x) for x in availability_zones])
            if get_tag(instance.tags, 'Name') in stups_names:
                terminitate_nat_instance(instance, instance.subnet.availability_zone)


def cleanup_vpc(account: AccountData, region: str):
    ec2 = account.session.resource('ec2', region)
    ec2c = account.session.client('ec2', region)

    with ActionOnExit('Delete Nat Gateways..'):
        for gateway in ec2c.describe_nat_gateways()['NatGateways']:
            if gateway['State'] == 'available':
                if account.domain is not None and gateway.get('NatGatewayAddresses', {})[0].get('PublicIp'):
                    delete_dns_record(account,
                                      'nat-{}'.format(ec2.Subnet(gateway['SubnetId']).availability_zone),
                                      gateway.get('NatGatewayAddresses', {})[0].get('PublicIp'))
                if gateway['State'] in ('pending', 'available'):
                    ec2c.delete_nat_gateway(NatGatewayId=gateway['NatGatewayId'])
    filters = [
        {'Name': 'state', 'Values': ['pending', 'available', 'deleting']}
    ]
    nat_gateway = ec2c.describe_nat_gateways(Filter=filters)['NatGateways']
    while len(nat_gateway) and nat_gateway[0]['State'] == 'deleting':
        warning('Nat Gateway is deleting.. waiting..')
        time.sleep(10)
        nat_gateway = ec2c.describe_nat_gateways(Filter=filters)['NatGateways']

    with ActionOnExit('Delete Endpoints..'):
        for endpoint in ec2c.describe_vpc_endpoints()['VpcEndpoints']:
            ec2c.delete_vpc_endpoints(VpcEndpointIds=[endpoint['VpcEndpointId']])

        while len(ec2c.describe_vpc_endpoints()['VpcEndpoints']) > 0:
            warning('VPC Endpoint is deleting.. waiting..')
            time.sleep(10)

    with ActionOnExit('Delete Subnets..'):
        for subnet in ec2c.describe_subnets()['Subnets']:
            ec2c.delete_subnet(SubnetId=subnet['SubnetId'])

    with ActionOnExit('Delete Routing Table..'):
        for route_table in ec2c.describe_route_tables()['RouteTables']:
            if not route_table['Associations'] or not route_table['Associations'][0]['Main']:
                ec2c.delete_route_table(RouteTableId=route_table['RouteTableId'])

    with ActionOnExit('Delete non default VPCs..'):
        for vpc in ec2c.describe_vpcs()['Vpcs']:
            if not vpc['IsDefault']:
                ec2c.delete_vpc(VpcId=vpc['VpcId'])

    with ActionOnExit('Delete Elastic IPs..'):
        for eip in ec2c.describe_addresses()['Addresses']:
            ec2c.release_address(AllocationId=eip['AllocationId'])


def get_sg(name: str, desc: str, sgs: list) -> object:
    for sg in sgs:
        if sg.group_name == name and sg.description == desc:
            return sg


def allow_https_vpc_cidr(permissions: list, vpc_cidr: str) -> bool:
    for permission in permissions:
        if (
            permission['IpProtocol'] == 'tcp'
            and permission['FromPort'] == 443
            and permission['ToPort'] == 443
            and {'CidrIp': vpc_cidr} in permission['IpRanges']
        ):
            return True
