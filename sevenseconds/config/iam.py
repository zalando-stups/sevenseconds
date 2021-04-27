import copy
import os

import botocore.exceptions
import gnupg
import json
import requests
from ..helper import fatal_error, info, ActionOnExit, error, warning
from ..config import AccountData


def configure_iam(account: AccountData):
    configure_iam_policy(account)
    configure_iam_saml(account)

    dns_domain = account.domain
    if dns_domain:
        configure_iam_certificate(account.session, dns_domain)
    else:
        warning('No DNS domain configured, skipping certificate management')


def effective_roles(config):
    roles = copy.deepcopy(config.get('roles', {}))

    for additional_policy in config.get('additional_policies', []):
        role_name = additional_policy['role']
        role = roles.get(role_name)
        if role is None or role.get('drop', False):
            raise ValueError("Found a custom policy for disabled or missing role {}".format(role_name))
        statement = role.get('policy', {}).get('Statement')
        if statement is None:
            raise ValueError("No policy statement found in role {}".format(role_name))
        statement.append(additional_policy['statement'])

    return roles


def effective_attached_policies(config, role_name, role_cfg):
    """Merge the attached_policies for a role and
    additional_attached_policies found in the account config for the
    given role. Note it might return duplicates."""
    attached_policies = role_cfg.get("attached_policies", [])
    additional_attached_policies = []
    for additional_attached_policy in config.get("additional_attached_policies", []):
        role = additional_attached_policy["role"]
        if role == role_name:
            additional_attached_policies += additional_attached_policy.get("policies", [])
    return attached_policies + additional_attached_policies


def configure_iam_policy(account: AccountData):
    iam = account.session.resource('iam')
    sts = account.session.client('sts')
    roles = effective_roles(account.config)
    current_arn = sts.get_caller_identity()['Arn']

    info('Account ID is {}'.format(account.id))

    for role_name, role_cfg in sorted(roles.items()):
        if role_cfg.get('drop', False):
            with ActionOnExit('Drop Role {role_name} if exist..', **vars()) as act:
                if current_arn.startswith('arn:aws:sts::{}:assumed-role/{}/'.format(account.id, role_name)):
                    act.warning('role in use')
                else:
                    try:
                        iam.Role(role_name).arn
                    except Exception:
                        act.ok('not found')
                    else:
                        try:
                            for policy in iam.Role(role_name).policies.all():
                                policy.delete()
                            for policy in iam.Role(role_name).attached_policies.all():
                                policy.detach_role(RoleName=role_name)
                            iam.Role(role_name).delete()
                            act.ok('dropped')
                        except Exception as e:
                            act.error(e)

        else:
            role = iam.Role(role_name)

            expected_assume_role_policy_document = json.loads(
                json.dumps(role_cfg.get('assume_role_policy')).replace('{account_id}', account.id))

            try:
                role.arn
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    with ActionOnExit('Creating role {role_name}..', **vars()):
                        iam.create_role(Path=role_cfg.get('path', '/'),
                                        RoleName=role_name,
                                        AssumeRolePolicyDocument=json.dumps(expected_assume_role_policy_document))
                else:
                    raise

            expected_policy_document = json.loads(
                json.dumps(role_cfg.get('policy')).replace('{account_id}', account.id))
            expected_policies = {role_name: expected_policy_document} if expected_policy_document else {}
            policies = {p.policy_name: p.policy_document for p in role.policies.all()}
            if policies != expected_policies:
                with ActionOnExit('Updating policy for role {role_name}..', **vars()) as act:
                    for name, document in expected_policies.items():
                        iam.RolePolicy(role_name, name).put(PolicyDocument=json.dumps(document))
                    for policy_name in policies:
                        if policy_name not in expected_policies:
                            act.warning('Deleting {} from {}'.format(policy_name, role_name))
                            iam.RolePolicy(role_name, policy_name).delete()

            if role.assume_role_policy_document != expected_assume_role_policy_document:
                with ActionOnExit('Updating assume role policy for role {role_name}..', **vars()):
                    updated_assume_role_policy_document = json.dumps(expected_assume_role_policy_document)
                    iam.AssumeRolePolicy(role_name).update(PolicyDocument=updated_assume_role_policy_document)

            configured_attached_policies = effective_attached_policies(account.config, role_name, role_cfg)
            attached_policies = set(p.arn for p in role.attached_policies.all())
            expected_attached_policies = set(
                policy.replace("{account_id}", account.id) for policy in configured_attached_policies
            )
            if attached_policies != expected_attached_policies:
                with ActionOnExit('Updating attached policies for {role_name}..', **vars()) as act:
                    for arn in attached_policies - expected_attached_policies:
                        act.warning('Detaching {} from {}'.format(arn, role_name))
                        iam.Policy(arn).detach_role(RoleName=role_name)
                    for arn in expected_attached_policies - attached_policies:
                        act.warning('Attaching {} to {}'.format(arn, role_name))
                        iam.Policy(arn).attach_role(RoleName=role_name)


def configure_iam_saml(account: AccountData):
    iam = account.session.resource('iam')
    for name, url in account.config.get('saml_providers', {}).items():
        arn = 'arn:aws:iam::{account_id}:saml-provider/{name}'.format(account_id=account.id, name=name)
        found = False
        for provider in iam.saml_providers.all():
            if provider.arn == arn:
                found = True
        if found:
            info('Found existing SAML provider {name}'.format(name=name))
            continue

        with ActionOnExit('Creating SAML provider {name}..', **vars()):
            if url.startswith('http'):
                r = requests.get(url)
                if r.status_code == 200:
                    saml_metadata_document = r.text
                else:
                    error('Error code: {}'.format(r.status_code))
                    error('Error msg: {}'.format(r.text))
            else:
                saml_metadata_document = url

            iam.create_saml_provider(SAMLMetadataDocument=saml_metadata_document, Name=name)


def configure_iam_certificate(session, dns_domain: str):
    iam = session.resource('iam')
    cert_name = dns_domain.replace('.', '-')
    certs = iam.server_certificates.all()
    cert_names = [d.name for d in certs]
    if cert_names:
        info('Found existing SSL certs: {}'.format(', '.join(cert_names)))
    else:
        info('No existing SSL certs found...')
    if cert_name not in cert_names:
        with ActionOnExit('Uploading SSL server certificate..') as act:
            dir = os.environ.get('SSLDIR')
            if dir and os.path.isdir(dir):
                dir += '/'
            else:
                dir = ''
            file = dir + '_.' + dns_domain
            try:
                with open(file + '.crt') as fd:
                    cert_body = fd.read()
                if os.path.isfile(file + '.key') and os.path.getsize(file + '.key') > 0:
                    with open(file + '.key') as fd:
                        private_key = fd.read()
                elif os.path.isfile(file + '.key.gpg') and os.path.getsize(file + '.key.gpg') > 0:
                    try:
                        gpg = gnupg.GPG(gnupghome=os.path.abspath(os.path.join(os.environ.get('HOME', '~'), '.gnupg')))
                    except TypeError:
                        fatal_error('Please install python-gnupg>=0.3.8 and remove gnupg>1.0.0!')
                    with open(file + '.key.gpg', 'rb') as fd:
                        gpg_obj = gpg.decrypt_file(fd)
                    if gpg_obj.ok:
                        private_key = gpg_obj.data
                    else:
                        act.error('decryption error: {}'.format(gpg_obj.stderr))
                        return
                with open(dir + 'trusted_chain_sha256.pem') as fd:
                    cert_chain = fd.read()
                try:
                    iam.create_server_certificate(
                        Path='/',
                        ServerCertificateName=cert_name,
                        CertificateBody=cert_body,
                        PrivateKey=private_key,
                        CertificateChain=cert_chain
                    )
                except Exception:
                    with open(dir + 'trusted_chain.pem') as fd:
                        cert_chain = fd.read()
                    iam.create_server_certificate(
                        Path='/',
                        ServerCertificateName=cert_name,
                        CertificateBody=cert_body,
                        PrivateKey=private_key,
                        CertificateChain=cert_chain
                    )
            except FileNotFoundError as e:
                act.error('Could not upload SSL cert: {}'.format(e))
