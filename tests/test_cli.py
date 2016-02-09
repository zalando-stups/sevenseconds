import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock
from sevenseconds.cli import cli, yaml


def test_print_version():
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--version'], catch_exceptions=False)

    assert 'AWS Account Configurator' in result.output
    assert 'unknown' not in result.output
    assert result.exit_code == 0


def test_configure_nonexisting_account(monkeypatch):
    runner = CliRunner()
    config = {'accounts': {}}
    monkeypatch.delenv('SAML_USER', raising=False)

    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as fd:
            yaml.safe_dump(config, fd)
        result = runner.invoke(cli, ['configure', 'config.yaml', 'myaccount'], catch_exceptions=False)

    assert 'No configuration found for account myaccount' in result.output


def test_configure_nonexisting_multi_account(monkeypatch):
    runner = CliRunner()
    config = {'accounts': {}}
    monkeypatch.delenv('SAML_USER', raising=False)

    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as fd:
            yaml.safe_dump(config, fd)
        result = runner.invoke(cli, ['configure', 'config.yaml', 'myaccount', 'dummyaccount'], catch_exceptions=False)

    assert 'No configuration found for account myaccount, dummyaccount' in result.output


def test_configure(monkeypatch):

    myboto3 = MagicMock(list_account_aliases=lambda *args, **vargs: {'AccountAliases': ['myaccount']},
                        describe_availability_zones=lambda *args, **vargs: {
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
    monkeypatch.setattr('boto3.client', lambda *args: myboto3)
    monkeypatch.setattr('keyring.get_password', MagicMock())
    monkeypatch.delenv('SAML_USER', raising=False)

    runner = CliRunner()

    config = {
        'global': {
            'base_ami': {
                'name': 'MyBaseAmi*',
                'is_public': False
            },
            'regions': ['region-1'],
            'cloudtrail': {
                's3_bucket_name': 'mybucket',
                's3_key_prefix': 'myprefix'
            },
            'domain': '{account_name}.example.org'
        },
        'accounts': {
            'myaccount': {},
            'mystaging': {}
            }}

    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as fd:
            yaml.safe_dump(config, fd)
        result = runner.invoke(cli, ['configure', 'config.yaml', 'my*'], catch_exceptions=False)

    assert 'Start configuration of: myaccount, mystaging' in result.output
    assert 'SAML User still missing. Please add with --saml-user or use the ENV SAML_USER' in result.output
    # Supports only SAML Login at the moment
    # assert 'Creating VPC for 172.31.0.0/16.. OK' in result.output
    # assert 'Enabling CloudTrail.. OK' in result.output
    assert result.exit_code == 0


if __name__ == '__main__':
    pytest.main()
