========================================
Seven Seconds - AWS Account Configurator
========================================

.. image:: https://travis-ci.org/zalando/aws-account-configurator.svg?branch=master
   :target: https://travis-ci.org/zalando/aws-account-configurator
   :alt: Travis CI build status

.. image:: https://coveralls.io/repos/zalando/aws-account-configurator/badge.svg?branch=master
   :target: https://coveralls.io/r/zalando/aws-account-configurator?branch=master
   :alt: Coveralls status

Command line utility to configure AWS accounts:

* Enable CloudTrail
* Configure VPC subnets (DMZ and internal)
* Configure NAT instances and routing
* Configure DNS
* Upload SSL cert
* Configure RDS/ElastiCache subnet groups
* Configure IAM roles
* Configure SAML integration
* Configure `SSH bastion host`_ ("odd")

Usage
=====

First install with PIP:

.. code-block:: bash

    $ sudo pip3 install --upgrade aws-account-configurator

Run with your YAML configuration (you need valid AWS credentials for this):

.. code-block:: bash

    $ aws-account-configurator myconfig.yaml myaccountname

Running from Source
===================

.. code-block:: bash

    $ python3 -m aws_account_configurator configure myconfig.yaml myaccountname


.. _SSH bastion host: https://github.com/zalando-stups/odd
