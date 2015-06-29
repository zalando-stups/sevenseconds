import pytest
from mock import MagicMock
from sevenseconds.aws import get_account_id, get_az_names
from datetime import datetime
import botocore.exceptions


def test_get_account_id(monkeypatch):
    conn = MagicMock(get_user=lambda: {'User': {
        'Path': '/',
        'UserName': 'test',
        'UserId': 'AIABCDEFG',
        'Arn': 'arn:aws:iam::01234567:user/test',
        'CreateDate': datetime(2015, 1, 1),
        'PasswordLastUsed': datetime(2015, 1, 1)
        }})
    monkeypatch.setattr('boto3.client', lambda x: conn)
    id = get_account_id()
    assert id == '01234567', 'ID from current User'

    conn = MagicMock(
        get_user=MagicMock(side_effect=botocore.exceptions.ClientError({
            'Error': {
                'Code': 'ValidationError',
                'Message': 'Must specify userName when calling with non-User credentials'}},
            'GetUser')),
        list_roles=lambda: {
            'Roles': [
                {
                    'Path': '/',
                    'RoleName': 'test-role',
                    'RoleId': 'string',
                    'Arn': 'arn:aws:iam::01234567:role/test-role',
                    'CreateDate': datetime(2015, 1, 1),
                    'AssumeRolePolicyDocument': {
                        'Statement': [{
                            'Action': 'sts:AssumeRole',
                            'Effect': 'Allow',
                            'Principal': {'Service': 'ec2.amazonaws.com'},
                            'Sid': ''}],
                        'Version': '2008-10-17'}
                }],
            'IsTruncated': False,
            'NextToken': 'string'
        })
    monkeypatch.setattr('boto3.client', lambda x: conn)
    id = get_account_id()
    assert id == '01234567', 'ID from exisiting Role'

    conn = MagicMock(
        get_user=MagicMock(side_effect=botocore.exceptions.ClientError({
            'Error': {
                'Code': 'ValidationError',
                'Message': 'Must specify userName when calling with non-User credentials'}},
            'GetUser')),
        list_roles=lambda: {
            'Roles': [],
            'IsTruncated': False,
            'NextToken': 'string'},
        list_users=lambda: {
            'IsTruncated': False,
            'Users': [{
                'Arn': 'arn:aws:iam::1234567:user/test',
                'CreateDate': datetime(2015, 1, 1),
                'Path': '/',
                'UserId': 'AIABCEFG',
                'UserName': 'test'}]})
    monkeypatch.setattr('boto3.client', lambda x: conn)
    id = get_account_id()
    assert id == '1234567', 'ID from existing Users'

    conn = MagicMock(
        get_user=MagicMock(side_effect=botocore.exceptions.ClientError({
            'Error': {
                'Code': 'ValidationError',
                'Message': 'Must specify userName when calling with non-User credentials'}},
            'GetUser')),
        list_roles=lambda: {
            'Roles': [],
            'IsTruncated': False,
            'NextToken': 'string'},
        list_users=lambda: {
            'IsTruncated': False,
            'Users': []},
        create_role=lambda RoleName, AssumeRolePolicyDocument: {
            'Role': {
                'AssumeRolePolicyDocument': {
                    'Statement': [
                        {
                            'Principal': {'Service': ['ec2.amazonaws.com']},
                            'Effect': 'Allow',
                            'Action': ['sts:AssumeRole']
                        }]
                    },
                'RoleName': 'temp-sevenseconds-account-id',
                'Path': '/',
                'Arn': 'arn:aws:iam::01234567:role/temp-sevenseconds-account-id',
                'CreateDate': datetime(2015, 1, 1),
                'RoleId': 'string'}}
        )

    monkeypatch.setattr('boto3.client', lambda x: conn)
    id = get_account_id()
    assert id == '01234567', 'ID from temporay Role'


def test_get_az_names(monkeypatch):
    conn = MagicMock(describe_availability_zones=lambda **kargs: {
        'AvailabilityZones': [
            {
                'ZoneName': 'eu-west-1a',
                'RegionName': 'eu-west-1',
                'State': 'available',
                'Messages': []
            }, {
                'ZoneName': 'eu-west-1b',
                'RegionName': 'eu-west-1',
                'State': 'available',
                'Messages': []
            }, {
                'ZoneName': 'eu-west-1c',
                'RegionName': 'eu-west-1',
                'State': 'available',
                'Messages': []
            }]})
    monkeypatch.setattr('boto3.client', lambda x, y: conn)
    names = get_az_names('eu-west-1')
    assert 'eu-west-1b' in names, 'AZ found'

    conn = MagicMock(describe_availability_zones=lambda **kargs: {
        'AvailabilityZones': []})
    monkeypatch.setattr('boto3.client', lambda x, y: conn)
    names = get_az_names('eu-west-1')
    assert 'eu-west-1b' in names, 'AZ found from Cache'


if __name__ == '__main__':
    pytest.main()
