import time
import netaddr
from netaddr import IPNetwork
import botocore.exceptions
from ..helper import ActionOnExit, info, warning


def configure_security_groups(account: object, region: str, trusted_addresses: set, vpc: object):
    for sg_name, sg_config in account.config.get('security_groups', {}).items():
        if sg_config.get('ip_permissions'):
            create_update_security_group(account.session, region, sg_name, sg_config, trusted_addresses, vpc)
        elif sg_config.get('allow_from_trusted'):
            update_security_group(account.session, region, sg_name, trusted_addresses)


def chunks(collection, n):
    """ Yield successive n-sized chunks from collection.
    >>> a = chunks('a b c d e f g h i j k l m'.split(), 2)
    >>> a.__next__()
    ['a', 'b']
    >>> a.__next__()
    ['c', 'd']
    >>> a.__next__()
    ['e', 'f']
    >>> a.__next__()
    ['g', 'h']
    >>> a.__next__()
    ['i', 'j']
    >>> a.__next__()
    ['k', 'l']
    >>> a.__next__()
    ['m']
    >>> a.__next__()
    Traceback (most recent call last):
        ...
    StopIteration
    >>> a = chunks('a b c d e f g h i j k l m'.split(), 5)
    >>> a.__next__()
    ['a', 'b', 'c', 'd', 'e']
    >>> a.__next__()
    ['f', 'g', 'h', 'i', 'j']
    >>> a.__next__()
    ['k', 'l', 'm']
    >>> a.__next__()
    Traceback (most recent call last):
        ...
    StopIteration
    """
    for i in range(0, len(collection), n):
        yield collection[i:i + n]


def consolidate_networks(networks: set, min_prefixlen: int):
    '''
    >>> from pprint import pprint
    >>> test = [IPNetwork('10.47.0.0/17'),
    ...  IPNetwork('10.47.128.0/19'),
    ...  IPNetwork('10.47.168.0/21'),
    ...  IPNetwork('10.47.192.0/18'),
    ...  IPNetwork('10.48.0.0/16'),
    ...  IPNetwork('10.28.0.0/17'),
    ...  IPNetwork('10.28.128.0/19'),
    ...  IPNetwork('172.16.18.205/32'),
    ...  IPNetwork('172.16.48.0/20'),
    ...  IPNetwork('172.16.64.0/18'),
    ...  IPNetwork('172.16.128.0/17'),
    ...  IPNetwork('172.20.0.0/19'),
    ...  IPNetwork('172.20.57.229/32'),
    ...  IPNetwork('172.20.96.0/19'),
    ...  IPNetwork('172.20.128.0/17'),
    ...  IPNetwork('172.21.77.0/16'),
    ...  IPNetwork('173.124.7.8/32'),
    ...  IPNetwork('173.124.34.0/18'),
    ...  IPNetwork('173.93.160.0/19'),
    ...  IPNetwork('173.93.19.241/32'),
    ...  IPNetwork('173.93.25.95/32'),
    ...  IPNetwork('173.154.0.0/17'),
    ...  IPNetwork('173.154.128.0/18'),
    ...  IPNetwork('173.154.192.0/20'),
    ...  IPNetwork('193.99.144.85/32'),
    ...  IPNetwork('54.239.32.138/32'),
    ...  IPNetwork('91.240.34.5/32'),
    ...  IPNetwork('85.183.69.83/32'),
    ...  IPNetwork('95.100.66.202/32')]
    >>> pprint(consolidate_networks(test, 16))
    [IPNetwork('10.28.0.0/16'),
     IPNetwork('10.47.0.0/16'),
     IPNetwork('10.48.0.0/16'),
     IPNetwork('54.239.32.138/32'),
     IPNetwork('85.183.69.83/32'),
     IPNetwork('91.240.34.5/32'),
     IPNetwork('95.100.66.202/32'),
     IPNetwork('172.16.0.0/16'),
     IPNetwork('172.20.0.0/15'),
     IPNetwork('173.93.16.0/20'),
     IPNetwork('173.93.160.0/19'),
     IPNetwork('173.124.0.0/18'),
     IPNetwork('173.154.0.0/16'),
     IPNetwork('193.99.144.85/32')]
    '''
    networks = sorted([IPNetwork(net) for net in networks])
    new_networks = []
    for chunk in chunks(networks, 2):
        if len(chunk) > 1:
            spanning = netaddr.spanning_cidr(chunk)
            if spanning.prefixlen >= min_prefixlen:
                new_networks.append(spanning)
            else:
                new_networks.extend(chunk)
        else:
            new_networks.append(chunk[0])
    merged = netaddr.cidr_merge(new_networks)
    return merged


def update_security_group(session: object, region: str, sg_name: str, trusted_addresses: set):
    ec2 = session.resource('ec2', region)
    for sg in ec2.security_groups.filter(Filters=[{'Name': 'group-name', 'Values': [sg_name]}]):
        permission_count = len(sg.ip_permissions)
        if permission_count == 0:
            permission_count = 1
        networks = trusted_addresses
        prefixlen = 31
        while len(networks) > 50 / permission_count:
            networks = consolidate_networks(networks, prefixlen)
            prefixlen -= 1
        info('{}/{} Prefixlen: {}, {} networks: {}'.format(region, sg_name, prefixlen, len(networks), networks))
        for ip_permission in sg.ip_permissions:
            ipgrants = [IPNetwork('{}'.format(cidr['CidrIp'])) for cidr in ip_permission.get('IpRanges')]
            info('Entrys from {}: {} {} {} {}'.format(sg.group_name,
                                                      ip_permission['IpProtocol'],
                                                      ip_permission.get('FromPort'),
                                                      ip_permission.get('ToPort'),
                                                      ipgrants))
            for grant in ipgrants:
                if grant not in networks:
                    warning('Remove {} from security group {}'.format(grant, sg.group_name))
                    sg.revoke_ingress(IpPermissions=[
                        {
                            'IpProtocol': ip_permission['IpProtocol'],
                            'FromPort': ip_permission.get('FromPort'),
                            'ToPort': ip_permission.get('ToPort'),
                            'IpRanges': [
                                {
                                    'CidrIp': str(grant)
                                }
                            ]
                        }])
            with ActionOnExit('Updating security group {}..'.format(sg.group_name)) as act:
                for cidr in sorted(networks):
                    try:
                        sg.authorize_ingress(IpPermissions=[
                            {
                                'IpProtocol': ip_permission['IpProtocol'],
                                'FromPort': ip_permission.get('FromPort'),
                                'ToPort': ip_permission.get('ToPort'),
                                'IpRanges': [
                                    {
                                        'CidrIp': str(cidr)
                                    }
                                ]
                            }])
                    except botocore.exceptions.ClientError as e:
                        if e.response['Error']['Code'] != 'InvalidPermission.Duplicate':
                            raise
                    act.progress()


def parse_sg_config(sg_config: dict, networks: set):
    """
    >>> from pprint import pprint
    >>> sg_config = {'allow_from_trusted': True,
    ...              'ip_permissions': [{'from_port': 0,
    ...                                  'ip_protocol': 'tcp',
    ...                                  'ip_ranges': ['127.0.0.1/8'],
    ...                                  'to_port': 65535}]}
    >>> networks = set(['4.64.0.0/10',
    ...                 '10.2.0.0/15',
    ...                 '10.34.0.0/16',
    ...                 '10.50.0.0/15',
    ...                 '10.84.0.0/14'])
    >>> pprint(parse_sg_config(sg_config, networks))
    {'proto:tcp|from:0|to:65535': {'FromPort': 0,
                                   'IpProtocol': 'tcp',
                                   'ToPort': 65535,
                                   'ip_ranges': {IPNetwork('4.64.0.0/10'),
                                                 IPNetwork('10.2.0.0/15'),
                                                 IPNetwork('10.34.0.0/16'),
                                                 IPNetwork('10.50.0.0/15'),
                                                 IPNetwork('10.84.0.0/14'),
                                                 IPNetwork('127.0.0.1/8')}}}

    >>> sg_config = {'allow_from_trusted': True,
    ...              'ip_permissions': [{'from_port': 22,
    ...                                  'ip_protocol': 'tcp',
    ...                                  'ip_ranges': ['127.0.0.1/8'],
    ...                                  'to_port': 22}]}
    >>> networks = set()
    >>> pprint(parse_sg_config(sg_config, networks))
    {'proto:tcp|from:22|to:22': {'FromPort': 22,
                                 'IpProtocol': 'tcp',
                                 'ToPort': 22,
                                 'ip_ranges': {IPNetwork('127.0.0.1/8')}}}

    >>> sg_config = {'allow_from_trusted': True,
    ...              'ip_permissions': [{'from_port': 53,
    ...                                  'ip_protocol': 'udp',
    ...                                  'to_port': 53}]}
    >>> networks = set(['10.34.0.0/16'])
    >>> pprint(parse_sg_config(sg_config, networks))
    {'proto:udp|from:53|to:53': {'FromPort': 53,
                                 'IpProtocol': 'udp',
                                 'ToPort': 53,
                                 'ip_ranges': {IPNetwork('10.34.0.0/16')}}}
    """
    parsed = {}
    for ip_permission in sg_config.get('ip_permissions'):
        key_name = 'proto:{}|from:{}|to:{}'.format(ip_permission['ip_protocol'],
                                                   ip_permission.get('from_port'),
                                                   ip_permission.get('to_port'))
        ipgrants = set([IPNetwork('{}'.format(cidr)) for cidr in ip_permission.get('ip_ranges', [])])
        if sg_config.get('allow_from_trusted'):
            ipgrants.update([IPNetwork(cidr) for cidr in networks])
        parsed[key_name] = {
            'IpProtocol': ip_permission.get('ip_protocol'),
            'FromPort': ip_permission.get('from_port'),
            'ToPort': ip_permission.get('to_port'),
            'ip_ranges': ipgrants}
    return parsed


def create_update_security_group(
        session: object, region: str, sg_name: str, sg_config: dict, networks: set, vpc: object):
    parsed_sg_config = parse_sg_config(sg_config, networks)

    sg = [x for x in vpc.security_groups.all() if x.group_name == sg_name]
    if not sg:
        with ActionOnExit('Create new security group {}..'.format(sg_name)) as act:
            sg = vpc.create_security_group(
                GroupName=sg_name,
                Description=sg_config.get('description', 'Managed Security Group'))
            # We are to fast for AWS (InvalidGroup.NotFound)
            time.sleep(2)
            sg.create_tags(Tags=[{'Key': 'Name', 'Value': sg_name}])
    else:
        sg = sg[0]

    for ip_permission in sg.ip_permissions:
        ipgrants = [IPNetwork('{}'.format(cidr['CidrIp'])) for cidr in ip_permission.get('IpRanges')]
        info('Entrys from {}: {}'.format(sg.group_name, ip_permission))
        key_name = 'proto:{}|from:{}|to:{}'.format(ip_permission['IpProtocol'],
                                                   ip_permission.get('FromPort'),
                                                   ip_permission.get('ToPort'))
        if key_name not in parsed_sg_config:
            warning('Remove Entry from {}: {}'.format(sg.group_name, ip_permission))
            sg.revoke_ingress(IpPermissions=[ip_permission])
            continue

        for grant in ipgrants:
            if grant not in parsed_sg_config[key_name]['ip_ranges']:
                warning('Remove {} from security group {}'.format(grant, sg.group_name))
                sg.revoke_ingress(IpPermissions=[
                    {
                        'IpProtocol': ip_permission['IpProtocol'],
                        'FromPort': ip_permission.get('FromPort'),
                        'ToPort': ip_permission.get('ToPort'),
                        'IpRanges': [
                            {
                                'CidrIp': str(grant)
                            }
                        ]
                    }])
            else:
                parsed_sg_config[key_name]['ip_ranges'].remove(grant)

    with ActionOnExit('Updating security group {}..'.format(sg.group_name)) as act:
        for key, conf in parsed_sg_config.items():
            for cidr in sorted(conf['ip_ranges']):
                try:
                    sg.authorize_ingress(IpPermissions=[
                        {
                            'IpProtocol': conf['IpProtocol'],
                            'FromPort': conf['FromPort'],
                            'ToPort': conf['ToPort'],
                            'IpRanges': [
                                {
                                    'CidrIp': str(cidr)
                                }
                            ]
                        }])
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidPermission.Duplicate':
                        raise
                act.progress()
