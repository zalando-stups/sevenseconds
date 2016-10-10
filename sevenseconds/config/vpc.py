import time
import json
import re
import hashlib
from netaddr import IPNetwork
from ..helper import ActionOnExit, info, warning
from ..helper.network import calculate_subnet
from ..helper.aws import filter_subnets, get_tag, get_az_names, associate_address
from .ami import get_base_ami_id
from .route53 import configure_dns_record, delete_dns_record
from clickclick import OutputFormat
from clickclick.console import print_table

VPC_NET = IPNetwork('172.31.0.0/16')


def configure_vpc(account, region):
    ec2 = account.session.resource('ec2', region)
    ec2c = account.session.client('ec2', region)
    vpc_net = VPC_NET
    if 'vpc_net' in account.config and region in account.config['vpc_net']:
        vpc_net = IPNetwork(account.config['vpc_net'][region]['network'])
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
            ami_id = get_base_ami_id(account, region)
            tags = [{'Key': 'Name', 'Value': '{}-{}'.format(account.name, region)},
                    {'Key': 'LastUpdate', 'Value': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
                    ]
            for key, val in account.config.get('vpc', {}).get('tags', {}).items():
                tags.append({
                    'Key': key,
                    'Value': val.replace('{{ami_id}}', ami_id).replace(
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
    for _type in 'dmz', 'internal':
        for i, az in enumerate(sorted(availability_zones)):
            net = calculate_subnet(vpc_net, _type, i)
            configure_subnet(vpc, az, _type, net, account.dry_run, ec2c.get_waiter('subnet_available'))

    nat_instances = create_nat_instances(account, vpc, region)
    create_routing_tables(vpc, nat_instances)
    create_vpc_endpoints(account, vpc, region)
    return vpc


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


def configure_subnet(vpc, az, _type: str, cidr: IPNetwork, dry_run: bool, waiter):
    name = '{}-{}'.format(_type, az)
    subnet = find_subnet(vpc, cidr)
    if not subnet:
        with ActionOnExit('Creating subnet {name} with {cidr}..', **vars()):
            if not dry_run:
                subnet = vpc.create_subnet(CidrBlock=str(cidr), AvailabilityZone=az)
                waiter.wait(SubnetIds=[subnet.id], Filters=[
                    {'Name': 'cidrBlock',
                     'Values': [str(cidr)]},
                    {'Name': 'availabilityZone',
                     'Values': [az]}
                ])
                # We are to fast for AWS (InvalidSubnetID.NotFound)
                subnet.create_tags(Tags=[
                    {'Key': 'Name',
                     'Value': name}
                ])


def find_subnet(vpc: object, cidr):
    for subnet in vpc.subnets.all():
        if subnet.cidr_block == str(cidr):
            return subnet


def create_nat_instances(account: object, vpc: object, region: str):
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
        except:
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
                        ClientToken=sg_name
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

        configure_dns_record(account, 'nat-{}'.format(az_name), ip)
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


def create_routing_tables(vpc: object, nat_instance_by_az: dict):
    for route_table in vpc.route_tables.all():
        for association in route_table.associations.all():
            if association.main:
                for igw in vpc.internet_gateways.all():
                    route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                             GatewayId=igw.id)
                route_table.create_tags(Tags=[{'Key': 'Name', 'Value': 'DMZ Routing Table'}])

    for subnet in filter_subnets(vpc, 'internal'):
        route_table = None
        for rt in vpc.route_tables.all():
            if get_tag(rt.tags, 'Name', 'undef-rt-name') == get_tag(subnet.tags, 'Name', 'undef-subnet-name'):
                route_table = rt
                break
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
                    if route.state == 'blackhole':
                        act.warning('replace route')
                        vpc.meta.client.delete_route(RouteTableId=route_table.id,
                                                     DestinationCidrBlock='0.0.0.0/0')
                    else:
                        found_default_route = True
            if not found_default_route:
                act.warning('fix default route')
                route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                         **destination)
        with ActionOnExit('Associating route table..'):
            route_table.associate_with_subnet(SubnetId=subnet.id)


def create_vpc_endpoints(account: object, vpc: object, region: str):
    ec2c = account.session.client('ec2', region)
    router_tables = set([rt.id for rt in vpc.route_tables.all()])
    service_names = ec2c.describe_vpc_endpoint_services()['ServiceNames']

    for service_name in service_names:
        if service_name.endswith('.s3'):
            with ActionOnExit('Checking S3 VPC Endpoints..') as act:
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
                            act.warning('missmatch ({} vs. {}), make update: {}'.format(
                                rt_in_endpoint,
                                router_tables,
                                ec2c.modify_vpc_endpoint(**options))
                            )
                else:
                    options = {
                        'VpcId': vpc.id,
                        'ServiceName': service_name,
                        'RouteTableIds': list(router_tables),
                        'ClientToken': hashlib.md5(
                            '{}-{}:{}'.format(
                                region,
                                vpc.id,
                                sorted(list(router_tables))
                            ).encode('utf-8')).hexdigest()
                    }
                    act.warning('missing, make create: {}'.format(ec2c.create_vpc_endpoint(**options)))


def if_vpc_empty(account: object, region: str):
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


def delete_nat_host(account: object, region: str):
    ec2 = account.session.resource('ec2', region)
    availability_zones = get_az_names(account.session, region)
    for instance in ec2.instances.all():
        if instance.state.get('Name') in ('running', 'pending', 'stopping', 'stopped'):
            if instance.public_ip_address:
                delete_dns_record(account,
                                  'nat-{}'.format(instance.subnet.availability_zone),
                                  instance.public_ip_address)
            # Drop Bastion and NAT Instances
            stups_names = tuple(['NAT {}'.format(x) for x in availability_zones])
            if get_tag(instance.tags, 'Name') in stups_names:
                terminitate_nat_instance(instance, instance.subnet.availability_zone)


def cleanup_vpc(account: object, region: str):
    ec2 = account.session.resource('ec2', region)
    ec2c = account.session.client('ec2', region)

    with ActionOnExit('Delete Nat Gateways..'):
        for gateway in ec2c.describe_nat_gateways()['NatGateways']:
            if gateway['State'] == 'available':
                if gateway.get('NatGatewayAddresses', {})[0].get('PublicIp'):
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
