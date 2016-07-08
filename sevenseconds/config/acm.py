from ..helper import ActionOnExit, info


def configure_acm(account: object, region):
    config = account.config.get('acm')
    if not config or not config.get('domain_name') or not config.get('validation_domain'):
        info('No ACM configuration found. Skip ACM Cert requests')
        return
    domains = {}
    cert_domain_name = config['domain_name'].format(account_name=account.name)
    domains[cert_domain_name] = config['validation_domain'].format(account_name=account.name)
    for domain_name, validation_domain in config.get('subject_alternative_names', {}).items():
        domains[domain_name.format(account_name=account.name)] = validation_domain.format(account_name=account.name)

    acm = account.session.client('acm', region)
    certificate_list = acm.list_certificates()['CertificateSummaryList']
    if not certificate_list:
        request_acm_cert(acm, cert_domain_name, domains)
    else:
        found_cert = False
        with ActionOnExit('Check existing Certificates..') as act:
            for cert_summary in certificate_list:
                cert = acm.describe_certificate(CertificateArn=cert_summary['CertificateArn'])['Certificate']
                if cert['Status'] == 'PENDING_VALIDATION':
                    with ActionOnExit('Certificate {} still Pending. Resend Validation...'
                                      .format(cert['CertificateArn'])):
                        for d in cert["DomainValidationOptions"]:
                            acm.resend_validation_email(
                                CertificateArn=cert['CertificateArn'],
                                Domain=d["DomainName"],
                                ValidationDomain=d["ValidationDomain"]
                            )
                domain_options = {}
                for options in cert['DomainValidationOptions']:
                    domain_options[options['DomainName']] = options['ValidationDomain']
                if domain_options == domains:
                    act.ok('found')
                    found_cert = True
            if not found_cert:
                act.warning('nothing found')
        if not found_cert:
            request_acm_cert(acm, cert_domain_name, domains)


def request_acm_cert(acm: object, cert_domain_name, domains):
    with ActionOnExit('Create Certificate Request for {}..'.format(', '.join(domains.keys()))):
        acm.request_certificate(
            DomainName=cert_domain_name,
            SubjectAlternativeNames=list(domains.keys()),
            IdempotencyToken='sevenseconds',
            DomainValidationOptions=[
                    {
                        'DomainName': d,
                        'ValidationDomain': v
                    } for d, v in domains.items()
                ]
            )
