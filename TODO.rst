=============
Open Features
=============

MFA-Confguration For Root User
==============================

Amazon doesn't support it yet via API. Feature Request is ongoing...

example code (possibly not runnable)

.. code-block:: python

    #!/usr/bin/python3

    import boto.iam
    import time
    import onetimepass as otp
    import base64
    from clickclick import Action


    def get_account_alias():
        conn = boto.iam.connect_to_region('eu-west-1')
        resp = conn.get_account_alias()
        return resp['list_account_aliases_response']['list_account_aliases_result']['account_aliases'][0]


    con = boto.iam.connect_to_region('eu-west-1')
    user = None
    account_alias = get_account_alias()
    try:
        user = con.get_user()['get_user_response']['get_user_result']['user']
    except:
        pass
    with Action('Configure MFA Token..') as act:
        if user.username == account_alias and user.arn.endswith(':root'):
            mfa_devices = con.get_all_mfa_devices()['list_mfa_devices_response']['list_mfa_devices_result']['mfa_devices']
            if not mfa_devices:
                act.progress()
                mfa = con.create_virtual_mfa_device(device_name='root-account-mfa-device', path=con.get_path())
                secret = base64.b64decode(mfa['create_virtual_mfa_device_response']['create_virtual_mfa_device_result']['virtual_mfa_device']['base_32_string_seed'])
                id1 = str(otp.get_hotp(secret, int(time.time()) // 30 - 1)).zfill(6)
                id2 = str(otp.get_totp(secret)).zfill(6)
                con.enable_mfa_device(user_name='root', serial_number=mfa['create_virtual_mfa_device_response']['create_virtual_mfa_device_result']['virtual_mfa_device']['serial_number'], auth_code_1=id1, auth_code_2=id2)
        else:
            act.warning('Skipping (root-account)')


Other nice Feature currently without API-Support
================================================

* Consulidate Billing
* Enable IAM-Access to Billings
* TAX Informations

