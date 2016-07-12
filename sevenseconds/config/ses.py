from ..helper import info
from .route53 import get_dns_record, configure_dns_record


def configure_ses(account: object, dns_domain):
    verify_domain(account, dns_domain)
    if False:
        # Not necessary for ACM. Maybe for later...
        if not get_dns_record(account, dns_domain, 'MX'):
            configure_dns_record(account, dns_domain, '10 inbound-smtp.eu-west-1.amazonaws.com', type='MX')
        else:
            info('Found MX Record. Skip ACM configuration')


def verify_domain(account: object, dns_domain):
    ses = account.session.client('ses', 'eu-west-1')
    verification_token = '"{}"'.format(ses.verify_domain_identity(Domain=dns_domain)['VerificationToken'])
    configure_dns_record(account, '_amazonses', verification_token, type='TXT')
