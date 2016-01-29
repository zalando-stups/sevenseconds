from ..helper import info, ActionOnExit


def get_base_ami_id(account: object, region: str):
    images = search_base_ami_ids(account.session, account.config, region)
    if not images:
        permit_base_image(account, region)
        images = search_base_ami_ids(account.session, account.config, region)
        if not images:
            raise Exception('No AMI found')
    most_recent_image = images[0]
    info('Most recent AMI is "{}" ({})'.format(most_recent_image.name, most_recent_image.id))
    return most_recent_image.id


def search_base_ami_ids(session: object, config: dict, region: str):
    ec2 = session.resource('ec2', region)
    base_ami = config['base_ami']
    name = base_ami['name']
    with ActionOnExit('Searching for latest "{}" AMI..'.format(name)) as act:
        filters = get_filter(**base_ami)
        images = sorted(ec2.images.filter(Filters=filters), key=lambda x: x.creation_date, reverse=True)
        if not images:
            act.error('no AMI found for Filter: {}'.format(filters))
        return images


def get_filter(name, is_public, owner_id, **kwargs):
    filters = [
        {'Name': 'name',
         'Values': [name]},
        {'Name': 'is-public',
         'Values': [str(is_public).lower()]},
        {'Name': 'state',
         'Values': ['available']},
        {'Name': 'root-device-type',
         'Values': ['ebs']}
        ]
    if owner_id:
        filters.append({'Name': 'owner-id',
                        'Values': [str(owner_id)]})
    return filters


def permit_base_image(account: object, region: str):
    ami_ec2 = account.ami_session.resource('ec2', region)
    base_ami = account.config['base_ami']
    name = base_ami['name']
    with ActionOnExit('Permit "{}" for "{}/{}"..'.format(name, account.id, account.alias)) as act:
        if ami_ec2:
            images = []
            for image in search_base_ami_ids(account.ami_session, account.config, region):
                if len(image.describe_attribute(Attribute='launchPermission')['LaunchPermissions']) < 10:
                    continue
                if image.modify_attribute(Attribute='launchPermission', OperationType='add', UserIds=[account.id]):
                    images.append(image.id)
                    act.progress()
                else:
                    act.warning('Error on Image {}/{}'.format(image.id, image.name))
        else:
            act.error('No connection to "base_ami_account"')
    if images:
        with ActionOnExit('Waiting of AWS-Sync'):
            ec2c = account.session.client('ec2', region)
            waiter = ec2c.get_waiter('image_available')
            waiter.wait(Filters=get_filter(**base_ami))
