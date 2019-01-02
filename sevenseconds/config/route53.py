from ..helper import ActionOnExit, error, info, warning
from ..helper.aws import get_account_id


def configure_dns(account: object):
    conn = account.session.client('route53')
    dns_domain = account.config.get('domain').format(account_name=account.name)
    zone = list(filter(lambda x: x['Name'] == dns_domain + '.',
                       conn.list_hosted_zones_by_name(DNSName=dns_domain + '.')['HostedZones']))
    if not zone:
        with ActionOnExit('Creating hosted zone..'):
            conn.create_hosted_zone(Name=dns_domain + '.',
                                    CallerReference='sevenseconds-' + dns_domain,
                                    HostedZoneConfig={'Comment': 'Public Hosted Zone'})
    zone = conn.list_hosted_zones_by_name(DNSName=dns_domain + '.')['HostedZones'][0]
    nameservers = conn.get_hosted_zone(Id=zone['Id'])['DelegationSet']['NameServers']
    info('Hosted zone for {} has nameservers {}'.format(dns_domain, nameservers))
    with ActionOnExit('Set up DNS Delegation..') as act:
        try:
            configure_dns_delegation(account.admin_session, dns_domain, nameservers)
        except Exception:
            raise
            act.error('DNS Delegation not possible')
    soa_ttl = account.config.get('domain_soa_ttl', '60')
    with ActionOnExit('Set SOA-TTL to {}..'.format(soa_ttl)):
        rr_list = conn.list_resource_record_sets(HostedZoneId=zone['Id'],
                                                 StartRecordType='SOA',
                                                 StartRecordName=zone['Name'])
        rr = rr_list['ResourceRecordSets'][0]['ResourceRecords']
        changebatch = {'Comment': 'updated SOA TTL',
                       'Changes': [{'Action': 'UPSERT',
                                    'ResourceRecordSet': {'Name': zone['Name'],
                                                          'Type': 'SOA',
                                                          'TTL': int(soa_ttl),
                                                          'ResourceRecords':rr}}]}
        conn.change_resource_record_sets(HostedZoneId=zone['Id'], ChangeBatch=changebatch)

    if (account.id == get_account_id(account.admin_session)):
        cleanup_delegation(account)
    return dns_domain


def configure_dns_delegation(admin_session: object, domain: str, nameservers: list, action: str = 'UPSERT'):
    route53 = admin_session.client('route53')
    zone_id = find_zoneid(domain, route53)
    if zone_id:
        response = route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Comment': 'DNS delegation for {}'.format(domain),
                'Changes': [
                    {
                        'Action': action,
                        'ResourceRecordSet': {
                            'Name': domain,
                            'Type': 'NS',
                            'TTL': 7200,
                            'ResourceRecords': [{'Value': x} for x in nameservers]
                        }
                    }
                ]
            }
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            info('Request for {} successful: {}'.format(domain, response['ResponseMetadata']['RequestId']))
        else:
            error('Request for {} failed: {}'.format(domain, response))
    else:
        error('Can\'t find any Zone for {}'. format(domain))


def get_dns_record(account, dnsname, record_type='A'):
    route53 = account.session.client('route53')
    zone_id = find_zoneid(dnsname, route53)
    if not zone_id:
        return
    result = route53.list_resource_record_sets(HostedZoneId=zone_id,
                                               StartRecordType=record_type,
                                               StartRecordName=dnsname,
                                               MaxItems='1')['ResourceRecordSets'][0]
    if not result:
        return
    if result['Name'] == dnsname and result['Type'] == record_type:
        return result
    else:
        return


def configure_dns_record(account, hostname, value, type='A', action='UPSERT'):
    if isinstance(value, list):
        values = value
    else:
        values = [value]
    route53 = account.session.client('route53')
    dns_domain = account.config.get('domain').format(account_name=account.name)
    domain = '.'.join([hostname, dns_domain])
    with ActionOnExit('{} DNS record {}: {}'
                      .format('Adding' if action == 'UPSERT' else 'Deleting', domain, values)) as act:
        zone_id = find_zoneid(domain, route53)
        if zone_id:
            response = route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    'Comment': 'DNS Entry for {}'.format(hostname),
                    'Changes': [
                        {
                            'Action': action,
                            'ResourceRecordSet': {
                                'Name': domain,
                                'Type': type,
                                'TTL': 600,
                                'ResourceRecords': [{'Value': x} for x in values]
                            }
                        }
                    ]
                }
            )
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                act.ok('Request for {} successful: {}'.format(domain, response['ResponseMetadata']['RequestId']))
            else:
                act.error('Request for {} failed: {}'.format(domain, response))
        else:
            act.error('Can\'t find any Zone for {}'. format(domain))


def delete_dns_record(account, hostname, value, type='A', action='UPSERT'):
    configure_dns_record(account, hostname, value, type, 'DELETE')


def find_zoneid(domain: str, route53: object):
    result = route53.list_hosted_zones()
    hosted_zones = result['HostedZones']
    while result['IsTruncated']:
        result = route53.list_hosted_zones(Marker=result['NextMarker'])
        hosted_zones.extend(result['HostedZones'])

    while domain != '':
        id = [x['Id'] for x in hosted_zones if x['Name'] == domain + '.']
        if not id:
            try:
                domain = '.'.join(domain.split('.')[1:])
            except Exception:
                domain = ''
        else:
            return id[0]
    return None


def cleanup_delegation(account: object):
    route53 = account.admin_session.client('route53')
    account_list = account.auth.get_aws_accounts()
    tld = account.config.get('domain').format(account_name='').strip('.')
    zone_id = find_zoneid(tld, route53)

    if not zone_id:
        return

    result = route53.list_resource_record_sets(
        HostedZoneId=zone_id,
        StartRecordName=tld,
        StartRecordType='NS')
    zone_entries = result['ResourceRecordSets']
    while (result['IsTruncated'] and result['NextRecordType'] == 'NS'):
        if 'NextRecordIdentifier' in result:
            result = route53.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordName=result['NextRecordName'],
                StartRecordType=result['NextRecordType'],
                StartRecordIdentifier=result['NextRecordIdentifier']
            )
        else:
            result = route53.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordName=result['NextRecordName'],
                StartRecordType=result['NextRecordType']
            )
        zone_entries.extend(result['ResourceRecordSets'])

    delegations = [x for x in zone_entries if x['Type'] == 'NS' and x['Name'] != tld + '.']
    to_delete = []
    for delegation in delegations:
        subpart = delegation['Name'].split('.')[0]
        matched = [x for x in account_list if x['name'] == subpart]
        if len(matched) == 1:
            # Enable/Disable
            if matched[0]['disabled']:
                to_delete.append(delegation)
        elif len(matched) > 0:
            error('Found more then 1 Account: {}'.format(matched))
        else:
            warning('Can\'t find an Account for "{}" (Nameservers: {})'.format(
                delegation['Name'],
                ', '.join([x['Value'] for x in delegation['ResourceRecords']])))
    for old_delegation in to_delete:
        configure_dns_delegation(
            account.admin_session,
            domain=old_delegation['Name'].strip('.'),
            nameservers=[x['Value'] for x in old_delegation['ResourceRecords']],
            action='DELETE')
