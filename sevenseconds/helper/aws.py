AZ_NAMES_BY_REGION = {}
PENDING_ASSOCIATIONS = {}


def filter_subnets(vpc: object, _type: str):
    for subnet in vpc.subnets.all():
        if get_tag(subnet.tags, 'Name', '').startswith(_type + '-'):
            yield subnet


def get_account_alias(session):
    conn = session.client('iam')
    return conn.list_account_aliases()['AccountAliases']


def set_account_alias(session, alias):
    conn = session.client('iam')
    conn.create_account_alias(AccountAlias=alias)


def get_account_id(session):
    sts = session.client('sts')
    return sts.get_caller_identity()['Account']


def get_az_names(session, region: str):
    names = AZ_NAMES_BY_REGION.get(region)
    if not names:
        conn = session.client('ec2', region)
        ec2_zones = conn.describe_availability_zones(Filters=[{'Name': 'state', 'Values': ['available']}])
        names = [z['ZoneName'] for z in ec2_zones['AvailabilityZones']]
        AZ_NAMES_BY_REGION[region] = names
    return names


def get_tag(tags: list, key: str, default=None, prefix=''):
    '''
    >>> tags = [{'Key': 'aws:cloudformation:stack-id',
    ...          'Value': 'arn:aws:cloudformation:eu-west-1:123:stack/test-123'},
    ...         {'Key': 'Name',
    ...          'Value': 'test-123'},
    ...         {'Key': 'StackVersion',
    ...          'Value': '123'}]
    >>> get_tag(tags, 'StackVersion')
    '123'
    >>> get_tag(tags, 'aws:cloudformation:stack-id')
    'arn:aws:cloudformation:eu-west-1:123:stack/test-123'
    >>> get_tag(tags, 'notfound') is None
    True
    >>> parameters = [{'ParameterKey': 'VpcId', 'ParameterValue': 'vpc-123321'},
    ...               {'ParameterKey': 'TaupageId', 'ParameterValue': 'ami-123321'},
    ...               {'ParameterKey': 'EIPAllocation', 'ParameterValue': 'eipalloc-123321'},
    ...               {'ParameterKey': 'SubnetId', 'ParameterValue': 'subnet-123321'},
    ...               {'ParameterKey': 'InstanceType', 'ParameterValue': 't2.micro'},
    ...               {'ParameterKey': 'OddRelease', 'ParameterValue': 'v123'}]
    >>> get_tag(parameters, 'TaupageId', prefix='Parameter')
    'ami-123321'
    >>> get_tag(parameters, 'OddRelease', prefix='Parameter')
    'v123'
    '''
    if isinstance(tags, list):
        found = [tag['{}Value'.format(prefix)] for tag in tags if tag['{}Key'.format(prefix)] == key]
        if len(found):
            return found[0]
    return default


def associate_address(ec2c: object, instance_id: str = None):
    addr = None
    for vpc_addresse in ec2c.describe_addresses()['Addresses']:
        if (vpc_addresse.get('AssociationId') is None and
                vpc_addresse.get('AllocationId') not in PENDING_ASSOCIATIONS.keys()):
            # use existing Elastic IP (e.g. to re-use IP from previous bastion host)
            addr = vpc_addresse
    if addr is None:
        addr = ec2c.allocate_address(Domain='vpc')
    if instance_id is None:
        PENDING_ASSOCIATIONS[addr.get('AllocationId')] = addr.get('PublicIp')
        return addr.get('AllocationId'), addr.get('PublicIp')
    else:
        ec2c.associate_address(InstanceId=instance_id,
                               AllocationId=addr.get('AllocationId'))
        return addr.get('PublicIp')
