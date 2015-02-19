========================
AWS Account Configurator
========================


#### <input> ####

# - api access key of root account
# - api secret key of root account
# - domain ("team.example.org")
# - SSL private key file for domain

#### constants ####

# region = eu-central-1
# AZs = eu-central-1a, eu-central-1b
# subnets:
#   eu-central-1a:
#      'dmz-eu-central-1a': '172.31.0.0/21'
#      'internal-eu-central-1a': '172.31.128.0/20'
#   eu-central-1b:
#      'dmz-eu-central-1b': '172.31.8.0/21'
#      'internal-eu-central-1b': '172.31.144.0/20'
# nat-ami = ami-xxxxxx
# nat-size = m3.medium
# S3 bucket = .....


#### CloudTrail ####

# if CloudTrail configured:
#    skip
# else:
#    configure CloudTrail in ALL regions to push logs to S3 bucket

#### VPC ####

# find default VPC
# if VPC has subnets:
#    skip
# else:
#    create subnets as defined above
#
#    find 'main' routing tables
#    connect both dmz subnets to 'main' routing tables
#
#    start a NAT instance in every 'dmz' subnet
#    create and assign Elastic IPs to NAT instances
#
#    create 'internal' routing tables
#    connect NAT from 'internal' routing tables to 'dmz' NAT instances
#    connect both internal subnets to their 'internal' routing tables

#### RDS / ElastiCache ####

# if subnet groups exist:
#    skip
# else:
#    create subnet groups

#### Route 53 ####

# if domain exist:
#    skip
# else:
#    create hosted zone
#    print out DNS IPs from hosted zone (for later manual configuration)

#### EC2 ####

# if domain-certificate exists:
#    skip
# else:
#    upload private key file for domain

#### IAM ####

# if 'Administrator' exists:
#    skip
# else:
#    create Administrator role from JSON template

# if 'PowerUser' exists:
#    skip
# else:
#    create PowerUser role from JSON template

# if 'ReadOnly' exists:
#    skip
# else:
#    create ReadOnly role from JSON template

# if SAML configured:
#    skip
# else:
#    configure SAML



