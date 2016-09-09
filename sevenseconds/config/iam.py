import os
import gnupg
import json
import requests
from ..helper import fatal_error, info, ActionOnExit, error


def configure_iam(account: object, dns_domain: str):
    configure_iam_policy(account)
    configure_iam_saml(account)
    configure_iam_certificate(account.session, dns_domain)


def configure_iam_policy(account: object):
    iam = account.session.resource('iam')

    roles = account.config.get('roles', {})

    info('Account ID is {}'.format(account.id))

    for role_name, role_cfg in sorted(roles.items()):
        if role_cfg.get('drop', False):
            with ActionOnExit('Drop Role {role_name} if exist..', **vars()) as act:
                try:
                    iam.Role(role_name).arn
                except:
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
            with ActionOnExit('Checking role {role_name}..', **vars()) as act:
                try:
                    role_policy = iam.RolePolicy(role_name, role_name)
                    if (role_policy.policy_document == role_cfg['policy'] and
                       len(list(role_policy.Role().policies.all())) == 1 and
                       len(list(iam.Role(role_name).attached_policies.all())) == 0):
                        continue
                    else:
                        act.error('missmatch')
                except:
                    act.error('Failed')

            try:
                iam.Role(role_name).arn
            except:
                with ActionOnExit('Creating role {role_name}..', **vars()):
                    policy_document = json.dumps(role_cfg.get('assume_role_policy')).replace('{account_id}', account.id)
                    iam.create_role(Path=role_cfg.get('path', '/'),
                                    RoleName=role_name,
                                    AssumeRolePolicyDocument=policy_document)

            with ActionOnExit('Updating policy for role {role_name}..', **vars()):
                iam.RolePolicy(role_name, role_name).put(PolicyDocument=json.dumps(role_cfg['policy']))

            with ActionOnExit('Removing invalid policies from role {role_name}..', **vars()) as act:
                for policy in iam.Role(role_name).policies.all():
                    if policy.name != role_name:
                        act.warning('Delete {} from {}'.format(policy.name, role_name))
                        policy.delete()
                for policy in iam.Role(role_name).attached_policies.all():
                    act.warning('Detach {} from {}'.format(policy.policy_name, role_name))
                    policy.detach_role(RoleName=role_name)


def configure_iam_saml(account: object):
    iam = account.session.resource('iam')
    for name, url in account.config.get('saml_providers', {}).items():
        arn = 'arn:aws:iam::{account_id}:saml-provider/{name}'.format(account_id=account.id, name=name)
        found = False
        for provider in iam.saml_providers.all():
            if provider.arn == arn:
                found = True
        if found:
            info('Found existing SAML provider {name}'.format(name=name))
        else:
            with ActionOnExit('Creating SAML provider {name}..', **vars()):
                r = requests.get(url)
                if r.status_code == 200:
                    saml_metadata_document = r.text
                    iam.create_saml_provider(SAMLMetadataDocument=saml_metadata_document, Name=name)
                else:
                    error('Error code: {}'.format(r.status_code))
                    error('Error msg: {}'.format(r.text))


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
                except:
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
