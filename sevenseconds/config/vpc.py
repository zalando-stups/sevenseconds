import time
import json
from netaddr import IPNetwork
from ..helper import ActionOnExit, info, warning
from ..helper.network import calculate_subnet
from ..helper.aws import filter_subnets, get_tag, get_az_names, associate_address
from .ami import get_base_ami_id
from .route53 import configure_dns_record

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
            tags = [{'Key': 'Name', 'Value': '{}-{}'.format(account.name, region)}]
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
    nat_instance_by_az = {}
    for subnet in filter_subnets(vpc, 'dmz'):
        az_name = subnet.availability_zone

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
             'Values': ['running', 'pending']},
        ]
        instances = list(ec2.instances.filter(Filters=filters))
        nat_gateway = None
        try:
            filters = [
                {'Name': 'subnet-id', 'Values': [subnet.id]},
                {'Name': 'state', 'Values': ['pending', 'available']}
            ]
            nat_gateway = ec2c.describe_nat_gateways(Filter=filters)['NatGateways']
            support_nat_gateway = True
        except:
            support_nat_gateway = False

        if nat_gateway:
            nat_instance_by_az[az_name] = {'NatGatewayId': nat_gateway[0]['NatGatewayId']}
            ip = [x['PublicIp'] for x in nat_gateway[0]['NatGatewayAddresses']]
        elif instances:
            instance = instances[0]
            nat_instance_by_az[az_name] = {'InstanceId': instance.id}
            ip = instance.public_ip_address
            if ip is None:
                with ActionOnExit('Associating Elastic IP..'):
                    ip = associate_address(ec2c, instance.id)

            with ActionOnExit('Disabling source/destination checks..'):
                instance.modify_attribute(SourceDestCheck={'Value': False})
            if support_nat_gateway:
                # FIXME Add NAT GW Migration
                warning('Skip migration from NAT Instance to NAT Gateway')
        else:
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

                if ip is None:
                    with ActionOnExit('Associating Elastic IP..'):
                        ip = associate_address(ec2c, instance.id)

                with ActionOnExit('Disabling source/destination checks..'):
                    instance.modify_attribute(SourceDestCheck={'Value': False})
                nat_instance_by_az[az_name] = {'InstanceId': instance.id}

        info('NAT {} {} is running with Elastic IP {}'.format('gateway' if support_nat_gateway else 'instance',
                                                              az_name,
                                                              ip))

        configure_dns_record(account, 'nat-{}'.format(az_name), ip)

    return nat_instance_by_az


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
        destination = nat_instance_by_az[subnet.availability_zone]
        if not route_table:
            with ActionOnExit('Creating route table {}..'.format(get_tag(subnet.tags, 'Name'))):
                route_table = vpc.create_route_table()
                route_table.create_tags(Tags=[{'Key': 'Name', 'Value': get_tag(subnet.tags, 'Name')}])
                route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                         **destination)

        with ActionOnExit('Checking route table..') as act:
            for route in route_table.routes:
                if route.get('DestinationCidrBlock') == '0.0.0.0/0':
                    if route['State'] == 'blackhole':
                        act.warning('replace route')
                        vpc.meta.client.delete_route(RouteTableId=route_table.id,
                                                     DestinationCidrBlock='0.0.0.0/0')
                        route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                                 **destination)
        with ActionOnExit('Associating route table..'):
            route_table.associate_with_subnet(SubnetId=subnet.id)
