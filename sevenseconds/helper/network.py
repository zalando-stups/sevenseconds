import multiprocessing
import os
import socket
import boto3
from netaddr import IPNetwork
from ..helper import ActionOnExit, info
from .aws import get_az_names


def calculate_subnet(vpc_net: IPNetwork, _type: str, az_index: int):
    '''
    >>> calculate_subnet(IPNetwork('10.0.0.0/16'), 'dmz', 0)
    IPNetwork('10.0.0.0/21')

    >>> calculate_subnet(IPNetwork('10.0.0.0/16'), 'internal', 0)
    IPNetwork('10.0.128.0/20')

    >>> calculate_subnet(IPNetwork('10.0.0.0/19'), 'dmz', 0)
    IPNetwork('10.0.0.0/24')

    >>> calculate_subnet(IPNetwork('10.0.0.0/19'), 'dmz', 1)
    IPNetwork('10.0.1.0/24')

    >>> calculate_subnet(IPNetwork('10.0.0.0/18'), 'dmz', 1)
    IPNetwork('10.0.2.0/23')

    >>> calculate_subnet(IPNetwork('10.0.0.0/19'), 'internal', 0)
    IPNetwork('10.0.16.0/23')

    >>> calculate_subnet(IPNetwork('10.0.0.0/19'), 'internal', 1)
    IPNetwork('10.0.18.0/23')

    >>> calculate_subnet(IPNetwork('10.0.0.0/18'), 'internal', 1)
    IPNetwork('10.0.36.0/22')

    >>> calculate_subnet(IPNetwork('10.0.0.0/28'), 'internal', 1)
    IPNetwork('10.0.0.9/32')

    >>> calculate_subnet(IPNetwork('10.0.0.0/30'), 'internal', 1)
    Traceback (most recent call last):
        ...
    netaddr.core.AddrFormatError: invalid IPNetwork 10.0.0.2/34

    >>> calculate_subnet(IPNetwork('10.0.0.0/64'), 'internal', 1)
    Traceback (most recent call last):
        ...
    netaddr.core.AddrFormatError: invalid IPNetwork 10.0.0.0/64
    '''
    if _type == 'dmz':
        networks = list(vpc_net.subnet(vpc_net.prefixlen + 5))
    else:
        # use the "upper half" of the /16 network for the internal/private subnets
        networks = list(list(vpc_net.subnet(vpc_net.prefixlen + 1))[1].subnet(vpc_net.prefixlen + 4))
    return networks[az_index]


def get_address(domain):
    with ActionOnExit('Checking {}'.format(domain)) as act:
        try:
            ai = socket.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
        except:
            ai = []
            act.error('n/a')
            pass
        for _, _, _, _, ip_port in ai:
            ip, _ = ip_port
            return '{}/32'.format(ip)


def get_trusted_addresses(session_data, config: dict):
    session = boto3.session.Session(**session_data)

    accounts = config.get('accounts', {})

    addresses = set()
    domains = set()
    for name, cidr in config.get('global', {}).get('trusted_networks', {}).items():
        info('Adding trusted network {} ({})'.format(name, cidr))
        addresses.add(cidr)

    for account_name, _cfg in accounts.items():
        cfg = {}
        cfg.update(config.get('global', {}))
        if _cfg:
            cfg.update(_cfg)
        for region in cfg['regions']:
            domains.update(['odd-{}.{}'.format(region, cfg.get('domain').format(account_name=account_name))])
            for az in get_az_names(session, region):
                domains.add('nat-{}.{}'.format(az, cfg.get('domain').format(account_name=account_name)))

    with multiprocessing.Pool(processes=os.cpu_count() * 20) as pool:
        addresses.update(pool.map(get_address, sorted(domains)))
    return addresses
