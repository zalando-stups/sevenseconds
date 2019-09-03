from ..helper import ActionOnExit


def configure_ebs_encryption(account, region):
    should_encrypt = account.config.get('ebs_encrypt_by_default', True)
    ec2 = account.session.client('ec2', region)
    with ActionOnExit("Checking EBS encryption by default") as act:
        result = ec2.get_ebs_encryption_by_default()
        if result['EbsEncryptionByDefault'] == should_encrypt:
            act.ok("already configured")
        elif should_encrypt:
            ec2.enable_ebs_encryption_by_default()
            act.ok("enabled")
        else:
            ec2.disable_ebs_encryption_by_default()
            act.ok("disabled")
