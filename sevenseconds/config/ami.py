from ..helper import ActionOnExit


def latest_ami(session: object, region: str, config: dict, channel: str):
    ec2 = session.resource('ec2', region)

    with ActionOnExit('Searching for latest "{}" AMI..'.format(channel)):
        filters = {"name": channel,
                   "is-public": "true" if config['is_public'] else "false",
                   "state": "available",
                   "root-device-type": "ebs",
                   "owner-id": config.get('owner_id')}

        images = sorted(ec2.images.filter(Filters=ami_filter(filters)), key=lambda x: x.creation_date, reverse=True)
        if images:
            return images[0].id
        else:
            return None


def ami_filter(predicates):
    return [{"Name": k, "Values": [str(v)]} for k, v in predicates.items() if v]


def latest_base_images(ami_session: object, region: str, config: dict):
    channels = set(config.get('channels', []))
    channels.add(config['default_channel'])

    return {channel: latest_ami(ami_session, region, config, channel) for channel in channels}


def configure_base_images(account: object, region: str, latest_images: dict):
    ec2 = account.session.resource('ec2', region)
    ami_ec2 = account.ami_session.resource('ec2', region)

    image_ids = list(filter(None, latest_images.values()))

    with ActionOnExit('Checking that all AMIs ({}) are available...'.format(', '.join(image_ids))):
        available_images = set(image.id for image in ec2.images.filter(ImageIds=image_ids))
        pending_image_ids = [image for image in image_ids if image not in available_images]

    if pending_image_ids:
        # Allow access from the AMI account
        for image in ami_ec2.images.filter(ImageIds=pending_image_ids):
            with ActionOnExit('Permit {} for "{}/{}"..'.format(image.id, account.id, account.alias)) as act:
                image.modify_attribute(Attribute='launchPermission', OperationType='add', UserIds=[account.id])

        # Wait until all images are available
        with ActionOnExit('Waiting of AWS-Sync') as act:
            for image in ec2.images.filter(ImageIds=pending_image_ids):
                image.wait_until_exists()
                act.progress()
