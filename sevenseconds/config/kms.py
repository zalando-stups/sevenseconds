from ..helper import ActionOnExit
from botocore.exceptions import ClientError
import json


# TODO:support reverting Drop:true operation by either cancelling deletion or recreating the keys
def configure_kms_keys(account: object, region):
    keys_config = account.config.get('kms', {})
    kms_client = account.session.client('kms', region)
    for key_alias in keys_config:
        key_config = keys_config[key_alias]
        if key_config.get('drop', False):
            schedule_key_deletion(kms_client, key_alias)
            continue
        key = json.loads(json.dumps(key_config).replace('{account_id}', account.id))
        with ActionOnExit('Searching for key "{}"..'.format(key_alias)) as act:
            try:
                alias = kms_client.describe_key(KeyId=key_alias)
                act.ok("key already exists, updating policy")
                put_key_response = kms_client.put_key_policy(
                    KeyId=alias["KeyMetadata"]["KeyId"],
                    PolicyName="default",
                    Policy=json.dumps(key["key_policy"]),
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
            except kms_client.exceptions.NotFoundException:
                create_response = kms_client.create_key(
                    Description=key['description'],
                    KeyUsage=key['key_usage'],
                    Origin='AWS_KMS',
                    BypassPolicyLockoutSafetyCheck=False,
                    Policy=json.dumps(key['key_policy']),
                    Tags=key['tags']
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


def schedule_key_deletion(kms_client, key_alias):
    with ActionOnExit('Checking deletion status for key "{}"..'.format(key_alias)) as act:
        try:
            describe_key_response = kms_client.describe_key(
                KeyId=key_alias
            )
        except ClientError as ex:
            if ex.response['Error']['Code'] == 'NotFoundException':
                act.ok('key {} cannot be found, probably deleted'.format(key_alias))
                return
            else:
                raise ex
        if describe_key_response['KeyMetadata']['KeyState'] == 'PendingDeletion':
            act.ok('key {} is already scheduled for deletion'.format(key_alias))
            return
        schedule_response = kms_client.schedule_key_deletion(
                                KeyId=describe_key_response['KeyMetadata']['KeyId'],
                                PendingWindowInDays=7,
                            )
        if schedule_response['ResponseMetadata']['HTTPStatusCode'] != 200:
            act.error(
                'failed to schedule key {} for deletion'
                .format(key_alias)
            )
            return
        act.ok('successfully scheduled key {} for deletion'.format(key_alias))
