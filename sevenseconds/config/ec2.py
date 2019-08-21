from ..helper import ActionOnExit


def configure_ebs_encryption(account, region):
    ec2 = account.session.client('ec2', region)
    with ActionOnExit("Checking EBS encryption by default") as act:
        result = ec2.get_ebs_encryption_by_default()
        if result['EbsEncryptionByDefault']:
            act.ok("already enabled")
        else:
            ec2.enable_ebs_encryption_by_default()
            act.ok("enabled")
