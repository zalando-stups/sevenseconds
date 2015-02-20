import pytest
from click.testing import CliRunner
from mock import MagicMock
from aws_account_configurator.cli import *

def test_print_version():
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--version'], catch_exceptions=False)

    assert 'AWS Account Configurator' in result.output
    assert result.exit_code == 0


def test_configure_nonexisting_account(monkeypatch):
    runner = CliRunner()
    config = {'accounts': {}}

    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as fd:
            yaml.safe_dump(config, fd)
        result = runner.invoke(cli, ['configure', 'config.yaml', 'myaccount'], catch_exceptions=False)

    assert 'No configuration found for account myaccount' in result.output


def test_configure(monkeypatch):

    monkeypatch.setattr('boto.vpc.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.ec2.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.cloudtrail.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.elasticache.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.rds2.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.route53.connect_to_region', MagicMock())
    monkeypatch.setattr('boto.iam.connect_to_region', MagicMock())
    monkeypatch.setattr('aws_account_configurator.cli.get_account_id', MagicMock())

    runner = CliRunner()

    config = {
        'global': {
            'regions': ['region-1'],
            'cloudtrail': {
                's3_bucket_name': 'mybucket',
                's3_key_prefix': 'myprefix'
            },
            'domain': '{account_name}.example.org'
        },
        'accounts': {'myaccount': {}}}

    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as fd:
            yaml.safe_dump(config, fd)
        result = runner.invoke(cli, ['configure', 'config.yaml', 'myaccount'], catch_exceptions=False)

    assert 'Creating VPC for 172.31.0.0/16.. OK' in result.output
    assert 'Enabling CloudTrail.. OK' in result.output
    assert result.exit_code == 0
