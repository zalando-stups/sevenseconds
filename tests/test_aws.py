import pytest
from unittest.mock import MagicMock
from sevenseconds.helper.aws import get_account_id, get_az_names
from sevenseconds.config.cloudtrail import configure_cloudtrail
from sevenseconds.config.s3 import configure_s3_buckets


def test_get_account_id(monkeypatch):
    sts = MagicMock(
        get_caller_identity=lambda: {
            "Account": "01234567",
            "Arn": "arn:aws:iam::01234567:assumed-role/Administrator/sevenseconds",
            "UserId": "ABCDEFGHIJKLMNOPQ:sevenseconds",
        }
    )
    session = MagicMock(client=MagicMock(return_value=sts))
    id = get_account_id(session)
    assert id == "01234567", "ID from current User"


def test_get_az_names(monkeypatch):
    conn = MagicMock(
        describe_availability_zones=lambda **kargs: {
            "AvailabilityZones": [
                {"ZoneName": "eu-west-1a", "RegionName": "eu-west-1", "State": "available", "Messages": []},
                {"ZoneName": "eu-west-1b", "RegionName": "eu-west-1", "State": "available", "Messages": []},
                {"ZoneName": "eu-west-1c", "RegionName": "eu-west-1", "State": "available", "Messages": []},
            ]
        }
    )
    session = MagicMock(client=MagicMock(return_value=conn))
    names = get_az_names(session, "eu-west-1")
    assert "eu-west-1b" in names, "AZ found"

    conn = MagicMock(describe_availability_zones=lambda **kargs: {"AvailabilityZones": []})
    session = MagicMock(client=MagicMock(return_value=conn))
    names = get_az_names(session, "eu-west-1")
    assert "eu-west-1b" in names, "AZ found from Cache"


def test_configure_cloudtrail(monkeypatch):
    def myinfo(text):
        assert "Found no Cloudtrail Section in Configfile." in text

    monkeypatch.setattr("clickclick.info", myinfo)
    account = MagicMock(name="name", config={})
    configure_cloudtrail(account)

    class _test:
        def _only_kwargs(f):
            def _filter(*args, **kwargs):
                if args or len(kwargs) == 0:
                    raise TypeError("{} only accepts keyword arguments.".format(f.__name__))
                return f(**kwargs)

            return _filter

        def describe_trails():
            return {
                "trailList": [
                    {
                        "IncludeGlobalServiceEvents": True,
                        "Name": "Default",
                        "S3BucketName": "bucketname",
                        "S3KeyPrefix": "",
                    }
                ]
            }

        @_only_kwargs
        def update_trail(Name, S3KeyPrefix, S3BucketName, IncludeGlobalServiceEvents, **kwargs):
            assert Name == "Default", "update Default"
            assert S3BucketName == "bucketname", "set bucketname"
            assert S3KeyPrefix == "", "set directory prefix"
            assert IncludeGlobalServiceEvents is True, "Include global"

        @_only_kwargs
        def create_trail(Name, S3KeyPrefix, S3BucketName, IncludeGlobalServiceEvents, **kwargs):
            assert Name == "Default", "update Default"
            assert S3BucketName == "bucketname", "set bucketname"
            assert S3KeyPrefix == "", "set directory prefix"
            assert IncludeGlobalServiceEvents is True, "Include global"

        @_only_kwargs
        def start_logging(Name):
            assert Name == "Default", "start logging for Default"

        @_only_kwargs
        def stop_logging(Name):
            assert Name == "wrongconfig", "stop wrong configuration"

        @_only_kwargs
        def delete_trail(Name):
            assert Name == "wrongconfig", "remove wrong configuration"

        @_only_kwargs
        def get_trail_status(Name):
            return {"IsLogging": True}

    account = MagicMock(
        name="name",
        config={"cloudtrail": {"s3_bucket_name": "bucketname", "s3_key_prefix": ""}},
        client=MagicMock(return_value=_test),
    )
    configure_cloudtrail(account)
    _test.get_trail_status = lambda Name: {"IsLogging": False}
    configure_cloudtrail(account)
    _test.get_trail_status = lambda Name: {"IsLogging": True}
    _test.describe_trails = lambda: {
        "trailList": [
            {
                "IncludeGlobalServiceEvents": False,
                "Name": "Default",
                "S3BucketName": "oldbucketname",
                "S3KeyPrefix": "dummy",
            }
        ]
    }
    configure_cloudtrail(account)
    _test.describe_trails = lambda: {
        "trailList": [
            {
                "IncludeGlobalServiceEvents": False,
                "Name": "wrongconfig",
                "S3BucketName": "oldbucketname",
                "S3KeyPrefix": "dummy",
            }
        ]
    }
    configure_cloudtrail(account)


def test_configure_s3_buckets():
    config = {
        "s3_buckets": {
            "bucket-1": {
                "name": "bucket-1",
                "regions": ["eu-central-1"],
                "lifecycle_configuration": {"Rules": [{"x": "y"}]},
                "encryption_config": {"Rules": [{"a": "b"}]},
                "tags": {"foo": "bar", "bee": "baz"},
            }
        }
    }
    account = MagicMock(config=config)
    s3 = account.session.resource("s3", "eu-central-1")
    bucket = s3.Bucket("bucket-1")
    bucket.creation_date = None

    configure_s3_buckets(account)

    bucket.create.assert_called_once()
    s3.BucketLifecycle("bucket-1").put.assert_called_once_with(LifecycleConfiguration={"Rules": [{"x": "y"}]})
    s3.meta.client.put_bucket_encryption.assert_called_once_with(
        Bucket="bucket-1", ServerSideEncryptionConfiguration={"Rules": [{"a": "b"}]}
    )
    bucket.Tagging().put.assert_called_once_with(
        Tagging={"TagSet": [{"Key": "foo", "Value": "bar"}, {"Key": "bee", "Value": "baz"}]}
    )


if __name__ == "__main__":
    pytest.main()
