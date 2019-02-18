import json
from ..helper import ActionOnExit, info


def configure_s3_buckets(account: object):
    for _, config in account.config.get('s3_buckets', {}).items():
        for region in config.get('regions', []):
            bucket_name = config['name'].format(account_id=account.id, region=region)
            s3 = account.session.resource('s3', region)
            with ActionOnExit('Checking S3 bucket {}..'.format(bucket_name)) as act:
                bucket = s3.Bucket(bucket_name)
                if not bucket.creation_date:
                    act.warning('not exist.. create bucket ..')
                    bucket.create(CreateBucketConfiguration={'LocationConstraint': region})
                    bucket.wait_until_exists()

            policy = config.get('policy', None)
            if policy is not None:
                with ActionOnExit('Updating policy for S3 bucket {}..'.format(bucket_name)):
                    policy_json = json.dumps(policy).replace('{bucket_name}', bucket_name)
                    bucket.Policy().put(Policy=policy_json)

            main_lifecycle_config = config.get('lifecycle_configuration')
            if main_lifecycle_config is not None:
                configure_bucket_lifecycle(s3, main_lifecycle_config, bucket_name)

            encryption_config = config.get('encryption_config')
            if encryption_config is not None:
                s3.meta.client.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration=encryption_config)

            tags = config.get('tags')
            if tags is not None:
                tag_set = []
                for k, v in tags.items():
                    tag_set.append({'Key': k, 'Value': v})
                bucket.Tagging().put(Tagging={'TagSet': tag_set})

            logging_target = config.get('logging_target', None)
            logging_lifecycle_config = config.get('logging_lifecycle_configuration')
            if logging_target is not None:
                logging_enabled = bucket.Logging().logging_enabled
                logging_target = logging_target.format(account_id=account.id, region=region)
                if logging_enabled and logging_target == logging_enabled['TargetBucket']:
                    info('Logging for {} to {}:{} enabled'.format(bucket.name,
                                                                  logging_enabled['TargetBucket'],
                                                                  logging_enabled['TargetPrefix']))
                else:
                    logging_bucket = create_logging_target(s3, logging_target, region)
                    enable_logging(bucket, logging_bucket)
                configure_bucket_lifecycle(s3, logging_lifecycle_config, logging_target)


def create_logging_target(s3: object, logging_target: str, region: str):
    with ActionOnExit('Check logging target {}'.format(logging_target)) as act:
        logging_bucket = s3.Bucket(logging_target)
        if not logging_bucket.creation_date:
            act.warning('not exist.. create bucket ..')
            logging_bucket.create(CreateBucketConfiguration={'LocationConstraint': region})
            logging_bucket.wait_until_exists()
        logging_bucket.Acl().put(ACL='log-delivery-write')
        return logging_bucket


def enable_logging(bucket: object, logging_bucket: object):
    with ActionOnExit('Enable logging for S3 bucket {} to {}..'.format(bucket.name,
                                                                       logging_bucket.name)):
        bucket.Logging().put(BucketLoggingStatus={
            'LoggingEnabled': {
                'TargetBucket': logging_bucket.name,
                'TargetPrefix': 'logs/'
                }
            }
        )


def configure_bucket_lifecycle(s3: object, lifecycle_config: dict, bucket: str):
    with ActionOnExit('Check lifecycle for bucket {}'.format(bucket)) as act:
        if lifecycle_config:
            logging_lifecycle = s3.BucketLifecycle(bucket)
            logging_lifecycle.put(LifecycleConfiguration=lifecycle_config)
        else:
            act.warning('skip')
