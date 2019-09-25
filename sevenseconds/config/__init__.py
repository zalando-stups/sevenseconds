from collections import namedtuple
from typing import NamedTuple, Optional

import boto3

from ..helper.auth import OAuthServices


class AccountData(NamedTuple):
    name: str  # Short Name of this Account
    alias: str  # Full AWS Account Alias Name (prefix + name)
    id: str  # AWS Account ID
    session: boto3.Session  # Boto3 Session for the current Account
    admin_session: boto3.Session  # Boto3 Session for the Admin Account (for DNS deligation)
    ami_session: boto3.Session  # Boto3 Session of the Taupage Owner Accounts (for EC2 AMI)
    config: dict  # Configuration of the current Account
    dry_run: bool  # dry-run boolean Flag
    options: dict  # Command Options dict
    auth: OAuthServices  # OAuthServices Object (exp. for Account List and AWS Credentials Service)

    @property
    def domain(self) -> Optional[str]:
        if self.config['domain'] is None:
            return None
        return self.config['domain'].format(account_name=self.name)


SharedData = namedtuple(
    'SharedData',
    (
        'base_images',  # {region -> {channel -> ami_id}}
        'trusted_addresses'
    ))
