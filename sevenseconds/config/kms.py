from ..helper import ActionOnExit


def configure_kms_keys(account: object):
    key_config = account.config.get('kms')
    kms_client = account.session.client('kms')
    for key_alias in key_config:
        with ActionOnExit('Searching for key "{}"..'.format(key_alias)) as act:
            key_tags = key_config[key_alias]['tags']
            converted_tags = []
            for tag in key_tags:
                for key in tag:
                    converted_tags.append({'TagKey': key, 'TagValue': tag[key]})
            # check if the key is present
            exist_aliases = kms_client.list_aliases()
            found = False
            for alias in exist_aliases['Aliases']:
                if alias['AliasName'] == key_alias:
                    found = True
                    act.ok('key already exists')
            if not found:
                create_response = kms_client.create_key(
                    Description='key used by deployment pipeline for secret encryption/decryption',
                    KeyUsage='ENCRYPT_DECRYPT',
                    Origin='AWS_KMS',
                    BypassPolicyLockoutSafetyCheck=False,
                    Tags=converted_tags
                )
                if create_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                    act.error('failed to create a key {} response: {}'.format(key_alias, create_response))
                    return
                key_id = create_response['KeyMetadata']['KeyId']
                alias_response = kms_client.create_alias(
                    AliasName=key_alias,
                    TargetKeyId=key_id
                )
                if alias_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                    act.error(
                        'failed to create alias {} with key_id {} response: {}'.format(key_alias, key_id, alias_response)
                    )
                    return
