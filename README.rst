========================================
Seven Seconds - AWS Account Configurator
========================================

.. image:: https://travis-ci.org/zalando-stups/sevenseconds.svg?branch=master
   :target: https://travis-ci.org/zalando-stups/sevenseconds
   :alt: Travis CI build status

.. image:: https://coveralls.io/repos/zalando-stups/sevenseconds/badge.svg?branch=master
   :target: https://coveralls.io/r/zalando-stups/sevenseconds?branch=master
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

See the `STUPS Landscape Overview`_.

Usage
=====

First install with PIP:

.. code-block:: bash

    $ sudo pip3 install --upgrade stups-sevenseconds

Run with your YAML configuration (you need valid AWS credentials for this):

.. code-block:: bash

    $ sevenseconds myconfig.yaml myaccountname

Running from Source
===================

.. code-block:: bash

    $ python3 -m sevenseconds configure myconfig.yaml myaccountname


.. _SSH bastion host: https://github.com/zalando-stups/odd
.. _STUPS Landscape Overview: https://zalando-stups.github.io/
