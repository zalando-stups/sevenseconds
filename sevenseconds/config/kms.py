from ..helper import ActionOnExit
import json


def configure_kms_keys(account: object):
    keys_config = account.config.get('kms')
    kms_client = account.session.client('kms')
    for key_alias in keys_config:
        key_config = keys_config[key_alias]
        key = json.loads(json.dumps(key_config)
            .replace('{account_id}', account.id))
        with ActionOnExit('Searching for key "{}"..'.format(key_alias)) as act:
            exist_aliases = kms_client.list_aliases()
            found = False
            for alias in exist_aliases['Aliases']:
                if alias['AliasName'] == key_alias:
                    found = True
                    act.ok('key already exists, updating policy')
                    put_key_response = kms_client.put_key_policy(
                        KeyId=alias['TargetKeyId'],
                        PolicyName='default',
                        Policy=json.dumps(key['KeyPolicy']),
                        BypassPolicyLockoutSafetyCheck=False
                    )
                    if put_key_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                        act.error(
                            'failed to update key policy for {} response: {}'
                            .format(key_alias, put_key_response)
                        )
                        break
                    act.ok("updated key policy for {}".format(key_alias))
                    break
            if not found:
                create_response = kms_client.create_key(
                    Description=key['Description'],
                    KeyUsage=key['KeyUsage'],
                    Origin='AWS_KMS',
                    BypassPolicyLockoutSafetyCheck=False,
                    Policy=json.dumps(key['KeyPolicy']),
                    Tags=key['Tags']
                )
                if create_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                    act.error('failed to create a key {} response: {}'.format(key_alias, create_response))
                    continue
                key_id = create_response['KeyMetadata']['KeyId']
                alias_response = kms_client.create_alias(
                    AliasName=key_alias,
                    TargetKeyId=key_id
                )
                if alias_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                    act.error(
                        'failed to create alias {} with key {} res:{}'
                        .format(key_alias, key_id, alias_response)
                    )
                    continue
