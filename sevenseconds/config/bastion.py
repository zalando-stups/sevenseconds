import time
import socket
import yaml
import datetime
import base64
import difflib
import botocore.exceptions
import requests
import json
from copy import deepcopy
from ..helper import info, warning, error, ActionOnExit, substitute_template_vars
from ..helper.aws import filter_subnets, associate_address, get_tag
from .ami import get_base_ami_id
from .route53 import configure_dns_record, delete_dns_record


def configure_bastion_host(account: object, vpc: object, region: str):
    ec2 = account.session.resource('ec2', region)
    cf = account.session.resource('cloudformation', region)
    cfc = account.session.client('cloudformation', region)

    re_deploy = account.config['bastion'].get('re_deploy', account.options.get('redeploy_odd_host'))

    bastion_version = None
    if account.config['bastion'].get('version_url'):
        with ActionOnExit('Get last Tag for Bastion Image...') as act:
            r = requests.get(account.config['bastion'].get('version_url'))
            if r.status_code != 200:
                act.error('Error code: {}'.format(r.status_code))
                act.error('Error msg: {}'.format(r.text))
                return
            tags = sorted(r.json(), key=lambda x: x['created'], reverse=True)
            bastion_version = tags[0]['name']
            act.ok(bastion_version)

    config = substitute_template_vars(account.config['bastion'].get('ami_config'),
                                      {'account_name': account.name,
                                       'vpc_net': str(vpc.cidr_block),
                                       'version': bastion_version})
    user_data = '#taupage-ami-config\n{}'.format(yaml.safe_dump(config)).encode('utf-8')
    ami_id = get_base_ami_id(account, region)

    # Search all existing hosts (Instances and Cloudformation)
    instance_filter = [
        {'Name': 'tag:Name',
         'Values': ['Odd (SSH Bastion Host)']},
        {'Name': 'instance-state-name',
         'Values': ['running', 'pending', 'stopping', 'stopped']},
    ]
    legacy_instances = list(vpc.instances.filter(Filters=instance_filter))
    for instance in legacy_instances:
        # Terminate old (stopped) Odd Systems
        if instance.state.get('Name') == 'stopped':
            drop_bastionhost(instance)
        else:
            # Verify Running Version (Userdate, FS Parameter)
            inst_user_data = base64.b64decode(instance.describe_attribute(Attribute='userData')['UserData']['Value'])
            if instance.image_id != ami_id:
                error('{} use {} instand of {}.'.format(instance.id, instance.image_id, ami_id))
                if re_deploy or account.options.get('update_odd_host'):
                    error(' ==> Make re-deploy')
                    re_deploy = True
            if inst_user_data != user_data:
                original = inst_user_data.decode('utf-8')
                new = user_data.decode('utf-8')
                diff = difflib.ndiff(original.splitlines(1), new.splitlines(1))
                error('{} use a different UserData\n{}'.format(instance.id, ''.join(diff)))
                if re_deploy or account.options.get('update_odd_host'):
                    error(' ==> Make re-deploy')
                    re_deploy = True
            launch_time = instance.launch_time
            if (not wait_for_ssh_port(instance.public_ip_address, 60) and
                    datetime.timedelta(minutes=15) < datetime.datetime.now(launch_time.tzinfo) - launch_time):
                error('Bastion Host does not response. Drop Bastionhost and create new one')
                drop_bastionhost(instance)
                legacy_instances = None

    # Start migration
    if legacy_instances and re_deploy:
        for instance in legacy_instances:
            drop_bastionhost(instance)
        legacy_instances = None

    update_needed = False

    # Check Odd Hosts in other vpcs
    cloudformation_filter = [
        {'Name': 'tag:aws:cloudformation:logical-id',
         'Values': ['OddServerInstance']},
        {'Name': 'instance-state-name',
         'Values': ['running', 'pending', 'stopping', 'stopped']},
    ]
    cloudformation_instances = list(vpc.instances.filter(Filters=cloudformation_filter))
    if cloudformation_instances:
        for instance in cloudformation_instances:
            # Terminate old (stopped) Odd Systems
            if instance.state.get('Name') == 'stopped':
                drop_bastionhost(instance)
            else:
                # Verify Running Version (Userdate, FS Parameter)
                oddstack = cf.Stack(get_tag(instance.tags, 'aws:cloudformation:stack-name'))

                used_ami_id = get_tag(oddstack.parameters, 'TaupageId', prefix='Parameter')
                if used_ami_id != ami_id:
                    error('{} use {} instand of {}.'.format(oddstack.name, used_ami_id, ami_id))
                    if re_deploy or account.options.get('update_odd_host'):
                        error(' ==> prepare change set')
                        update_needed = True
                used_bastion_version = get_tag(oddstack.parameters, 'OddRelease', prefix='Parameter')
                if used_bastion_version != bastion_version:
                    error('{} use {} instand of {}.'.format(oddstack.name, used_bastion_version, bastion_version))
                    if re_deploy or account.options.get('update_odd_host'):
                        error(' ==> prepare change set')
                        update_needed = True
                if update_needed or re_deploy:
                    update_cf_bastion_host(account, vpc, region, oddstack, ami_id, bastion_version)
                if not legacy_instances:
                    info('check old odd security groups')
                    cleanup_old_security_group(account, region, oddstack, vpc)

    if not legacy_instances and not cloudformation_instances:
        try:
            stack = cf.Stack('Odd')
            info('Stack Status: {}'.format(stack.stack_status))
        except:
            create_cf_bastion_host(account, vpc, region, ami_id, bastion_version)
        if stack.stack_status in ('UPDATE_IN_PROGRESS', 'CREATE_IN_PROGRESS'):
            if stack.stack_status.startswith('UPDATE_'):
                waiter = cfc.get_waiter('stack_update_complete')
            else:
                waiter = cfc.get_waiter('stack_create_complete')
            with ActionOnExit('Waiting of Stack') as act:
                try:
                    waiter.wait(StackName='Odd')
                except botocore.exceptions.WaiterError as e:
                    act.error('Stack creation failed: {}'.format(e))
                    return
            info('check old odd security groups')
            cleanup_old_security_group(account, region, stack, vpc)

        instance = ec2.Instance(stack.Resource(logical_id='OddServerInstance').physical_resource_id)
        launch_time = instance.launch_time
        if (not wait_for_ssh_port(instance.public_ip_address, 60) and
                datetime.timedelta(minutes=15) < datetime.datetime.now(launch_time.tzinfo) - launch_time):
            error('Bastion Host does not response. Force Update for Bastionhost Stack')
            update_cf_bastion_host(account, vpc, region, stack, ami_id, bastion_version)


def cleanup_old_security_group(account: object, region: str, oddstack: object, vpc: object):
    ec2 = account.session.resource('ec2', region)
    stack_security_group_id = oddstack.Resource(logical_id='OddSecurityGroup').physical_resource_id
    sgs = [x for x in vpc.security_groups.all() if x.group_name == 'Odd (SSH Bastion Host)']
    for sg in sgs:
        with ActionOnExit('Found old Odd Security Group {}/{}'.format(sg.id, sg.group_name)) as act:
            for sg_depency in vpc.meta.client.describe_security_groups(Filters=[
                        {
                            'Name': 'ip-permission.group-id',
                            'Values': [
                                sg.group_id,
                            ]
                        },
                    ])['SecurityGroups']:
                sg_depency = ec2.SecurityGroup(sg_depency.get('GroupId'))
                with ActionOnExit(
                        'Found old Odd SG depency in Security Group {}/{}'
                        .format(sg_depency.id, sg_depency.group_name)) as act:
                    for permission in sg_depency.ip_permissions:
                        _change_permission(sg_depency, permission, sg.group_id, stack_security_group_id, 'ingress', act)
                    for permission in sg_depency.ip_permissions_egress:
                        _change_permission(sg_depency, permission, sg.group_id, stack_security_group_id, 'egress', act)
            try:
                sg.delete()
                act.ok('removed')
            except Exception as e:
                act.error('Can\'t cleanup old Odd Stack: {}'.format(e))


def _change_permission(sg, permission, old_group_id, new_group_id, direction, act):
    old_permission = deepcopy(permission)
    replace = False
    for user_id_group_pair in permission.get('UserIdGroupPairs', []):
        if user_id_group_pair.get('GroupId') == old_group_id:
            user_id_group_pair['GroupId'] = new_group_id
            replace = True
        if permission.get('UserIdGroupPairs'):
            permission['UserIdGroupPairs'] = list(
                dict(
                    (v['GroupId'], v) for v in permission['UserIdGroupPairs']
                    ).values()
                )

    if replace:
        try:
            if direction == 'egress':
                sg.revoke_egress(IpPermissions=[old_permission])
            elif direction == 'ingress':
                sg.revoke_ingress(IpPermissions=[old_permission])
        except Exception as e:
            act.error('Can\'t revoke the Permissions: {}'.format(e))
        try:
            if direction == 'egress':
                sg.authorize_egress(IpPermissions=[permission])
            elif direction == 'ingress':
                sg.authorize_ingress(IpPermissions=[permission])
        except Exception as e:
            act.error('Can\'t authorize the Permissions: {}'.format(e))


def create_cf_bastion_host(account: object, vpc: object, region: str, ami_id: str, bastion_version: str):
    cf = account.session.resource('cloudformation', region)
    cfc = account.session.client('cloudformation', region)
    ec2c = account.session.client('ec2', region)

    subnet_ids = [a.id for a in filter_subnets(vpc, 'dmz')]
    if not subnet_ids:
        warning('No DMZ subnet found')
        return

    allocation_id, ip = associate_address(ec2c)
    stackname = 'Odd'
    stack = cf.create_stack(
        StackName=stackname,
        TemplateBody=json.dumps(account.config['bastion'].get('cf_template')),
        Parameters=[
            {
                'ParameterKey': 'AccountName',
                'ParameterValue': account.name
            },
            {
                'ParameterKey': 'DisableApiTermination',
                'ParameterValue': 'false'
            },
            {
                'ParameterKey': 'EIPAllocation',
                'ParameterValue': allocation_id
            },
            {
                'ParameterKey': 'OddRelease',
                'ParameterValue': bastion_version
            },
            {
                'ParameterKey': 'SubnetId',
                'ParameterValue': subnet_ids[0]
            },
            {
                'ParameterKey': 'TaupageId',
                'ParameterValue': ami_id
            },
            {
                'ParameterKey': 'VPCNetwork',
                'ParameterValue': str(vpc.cidr_block)
            },
            {
                'ParameterKey': 'VpcId',
                'ParameterValue': vpc.id
            }
        ],
        OnFailure='DELETE',
        Tags=[
                {'Key': 'LastUpdate', 'Value': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
        ]
    )
    with ActionOnExit('Wait of stack create complete') as act:
        waiter = cfc.get_waiter('stack_create_complete')
        try:
            waiter.wait(StackName=stack.name)
        except botocore.exceptions.WaiterError as e:
            act.error('Stack creation failed: {}'.format(e))
            return

    info('SSH Bastion instance is running with public IP {}'.format(ip))
    configure_dns_record(account, 'odd-{}'.format(region), ip)


def update_cf_bastion_host(account: object, vpc: object, region: str, stack: object, ami_id: str, bastion_version: str):
    cloudformation = account.session.client('cloudformation', region)

    # switch subnet, every update => force reinitialisation
    current_subnet = get_tag(stack.parameters, 'SubnetId', prefix='Parameter')
    subnet_ids = [a.id for a in filter_subnets(vpc, 'dmz')]
    if current_subnet in subnet_ids:
        subnet_ids.remove(current_subnet)

    if not subnet_ids:
        warning('No DMZ subnet found')
        return

    response = stack.update(
        TemplateBody=json.dumps(account.config['bastion'].get('cf_template')),
        Parameters=[
            {
                'ParameterKey': 'AccountName',
                'ParameterValue': account.name
            },
            {
                'ParameterKey': 'DisableApiTermination',
                'ParameterValue': 'false'
            },
            {
                'ParameterKey': 'EIPAllocation',
                'ParameterValue': get_tag(stack.parameters, 'EIPAllocation', prefix='Parameter')
            },
            {
                'ParameterKey': 'OddRelease',
                'ParameterValue': bastion_version
            },
            {
                'ParameterKey': 'SubnetId',
                'ParameterValue': subnet_ids[0]
            },
            {
                'ParameterKey': 'TaupageId',
                'ParameterValue': ami_id
            },
            {
                'ParameterKey': 'VPCNetwork',
                'ParameterValue': str(vpc.cidr_block)
            },
            {
                'ParameterKey': 'VpcId',
                'ParameterValue': vpc.id
            }
        ],
        Tags=[
            {'Key': 'LastUpdate', 'Value': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
        ]
    )
    info(response)
    with ActionOnExit('Wait of stack update complete') as act:
        waiter = cloudformation.get_waiter('stack_update_complete')
        try:
            waiter.wait(StackName=stack.name)
        except botocore.exceptions.WaiterError as e:
            act.error('Stack creation failed: {}'.format(e))
            return


def configure_bastion_host_deprecated(account: object, vpc: object, region: str):
    ec2c = account.session.client('ec2', region)
    cwc = account.session.client('cloudwatch', region)
    # account_name: str, dns_domain: str, ec2_conn, subnets: list, cfg: dict, vpc_net: IPNetwork
    try:
        subnet = list(filter_subnets(vpc, 'dmz'))[0]
    except:
        warning('No DMZ subnet found')
        return

    az_name = subnet.availability_zone
    # FIXME Add SG Check/Update for all Ho
    sg_name = 'Odd (SSH Bastion Host)'
    sg = [x for x in vpc.security_groups.all() if x.group_name == sg_name]
    if not sg:
        sg = vpc.create_security_group(GroupName=sg_name,
                                       Description='Allow SSH access to the bastion host')
        # We are to fast for AWS (InvalidGroup.NotFound)
        time.sleep(2)
        sg.create_tags(Tags=[{'Key': 'Name', 'Value': sg_name}])
        sg.authorize_ingress(IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            } for port in (22, 2222)])
    else:
        sg = sg[0]

    if account.config['bastion'].get('version_url'):
        with ActionOnExit('Get last Tag for Bastion Image...') as act:
            r = requests.get(account.config['bastion'].get('version_url'))
            if r.status_code != 200:
                act.error('Error code: {}'.format(r.status_code))
                act.error('Error msg: {}'.format(r.text))
                return
            tags = sorted(r.json(), key=lambda x: x['created'], reverse=True)
            config = substitute_template_vars(account.config['bastion'].get('ami_config'),
                                              {'account_name': account.name,
                                               'vpc_net': str(vpc.cidr_block),
                                               'version': tags[0]['name']})
    else:
        config = substitute_template_vars(account.config['bastion'].get('ami_config'),
                                          {'account_name': account.name, 'vpc_net': str(vpc.cidr_block)})
    user_data = '#taupage-ami-config\n{}'.format(yaml.safe_dump(config)).encode('utf-8')
    ami_id = get_base_ami_id(account, region)

    filters = [
        {'Name': 'tag:Name',
         'Values': [sg_name]},
        {'Name': 'instance-state-name',
         'Values': ['running', 'pending']},
    ]
    instances = list(vpc.instances.filter(Filters=filters))
    re_deploy = account.config['bastion'].get('re_deploy', account.options.get('redeploy_odd_host'))

    for instance in instances:
        inst_user_data = base64.b64decode(instance.describe_attribute(Attribute='userData')['UserData']['Value'])
        if instance.image_id != ami_id:
            error('{} use {} instand of {}.'.format(instance.id, instance.image_id, ami_id))
            if not re_deploy and account.options.get('update_odd_host'):
                error(' ==> Make re-deploy')
                re_deploy = True
        if inst_user_data != user_data:
            original = inst_user_data.decode('utf-8')
            new = user_data.decode('utf-8')
            diff = difflib.ndiff(original.splitlines(1), new.splitlines(1))
            error('{} use a different UserData\n{}'.format(instance.id, ''.join(diff)))
            if not re_deploy and account.options.get('update_odd_host'):
                error(' ==> Make re-deploy')
                re_deploy = True

    if instances and re_deploy:
        for instance in instances:
            drop_bastionhost(instance)
        instances = None

    if instances:
        instance = instances[0]
        ip = instance.public_ip_address
    else:
        with ActionOnExit('Launching SSH Bastion instance in {az_name}..', az_name=az_name):
            instance = subnet.create_instances(ImageId=ami_id,
                                               InstanceType=account.config['bastion'].get('instance_type', 't2.micro'),
                                               SecurityGroupIds=[sg.id],
                                               UserData=user_data,
                                               MinCount=1,
                                               MaxCount=1,
                                               DisableApiTermination=True,
                                               Monitoring={'Enabled': True})[0]

            waiter = ec2c.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instance.id])
            instance.create_tags(Tags=[{'Key': 'Name', 'Value': sg_name}])
            ip = None
            # FIXME activate Autorecovery !!
            cwc.put_metric_alarm(AlarmName='odd-host-{}-auto-recover'.format(instance.id),
                                 AlarmActions=['arn:aws:automate:{}:ec2:recover'.format(region)],
                                 MetricName='StatusCheckFailed',
                                 Namespace='AWS/EC2',
                                 Statistic='Minimum',
                                 Dimensions=[{
                                     'Name': 'InstanceId',
                                     'Value': instance.id
                                 }],
                                 Period=60,  # 1 minute
                                 EvaluationPeriods=2,
                                 Threshold=0,
                                 ComparisonOperator='GreaterThanThreshold')

    if ip is None:
        with ActionOnExit('Associating Elastic IP to {}..'.format(instance.id)):
            ip = associate_address(ec2c, instance.id)
    info('SSH Bastion instance is running with public IP {}'.format(ip))

    try:
        sg.revoke_egress(IpPermissions=[
            {
                'IpProtocol': '-1',
                'FromPort': -1,
                'ToPort': -1,
                'IpRanges': [
                    {
                        'CidrIp': '0.0.0.0/0'
                    }
                ]
            }])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidPermission.NotFound':
            pass
        else:
            raise
    rules = [
        # allow ALL connections to our internal EC2 instances
        ('tcp', 0, 65535, vpc.cidr_block),
        # allow HTTPS to the internet (actually only needed for SSH access service)
        ('tcp', 443, 443, '0.0.0.0/0'),
        # allow PostgreSQL to the internet (actually only needed for DBaaS)
        ('tcp', 5432, 5432, '0.0.0.0/0'),
        # allow pings
        ('icmp', -1, -1, '0.0.0.0/0'),
        # allow DNS
        ('udp', 53, 53, '0.0.0.0/0'),
        ('tcp', 53, 53, '0.0.0.0/0'),
    ]
    for proto, from_port, to_port, cidr in rules:
        try:
            sg.authorize_egress(IpPermissions=[
                {
                    'IpProtocol': str(proto),
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'IpRanges': [
                        {
                            'CidrIp': str(cidr)
                        }
                    ]
                }])
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'InvalidPermission.Duplicate':
                raise

    configure_dns_record(account, 'odd-{}'.format(region), ip)

    launch_time = instance.launch_time
    if (not wait_for_ssh_port(ip, 60) and
            datetime.timedelta(minutes=15) < datetime.datetime.now(launch_time.tzinfo) - launch_time):
        error('Bastion Host does not response. Drop Bastionhost and create new one')
        drop_bastionhost(instance)
        configure_bastion_host(account, vpc, region)


def drop_bastionhost(instance):
    with ActionOnExit('Terminating SSH Bastion host..'):
        instance.reload()
        if instance.state.get('Name') in ('running', 'pending', 'stopping', 'stopped'):
            instance.modify_attribute(Attribute='disableApiTermination', Value='false')
            instance.terminate()
            instance.wait_until_terminated()


def wait_for_ssh_port(host: str, timeout: int):
    start = time.time()
    with ActionOnExit('Waiting for SSH port of {}..'.format(host)) as act:
        while True:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                result = sock.connect_ex((host, 22))
            except:
                result = -1
            if result == 0:
                return True
            if time.time() - start > timeout:
                act.error('TIMEOUT')
                return False
            time.sleep(5)
            act.progress()


def delete_bastion_host(account: object, region: str):
    ec2 = account.session.resource('ec2', region)
    cf = account.session.resource('cloudformation', region)
    cfc = account.session.client('cloudformation', region)

    for instance in ec2.instances.all():
        if get_tag(instance.tags, 'Name') == 'Odd (SSH Bastion Host)':
            if instance.state.get('Name') in ('running', 'pending', 'stopping', 'stopped'):
                if instance.public_ip_address:
                    try:
                        delete_dns_record(account, 'odd-{}'.format(region), instance.public_ip_address)
                    except:
                        pass
                drop_bastionhost(instance)

    cloudformation_filter = [
        {'Name': 'tag:aws:cloudformation:logical-id',
         'Values': ['OddServerInstance']},
        {'Name': 'instance-state-name',
         'Values': ['running', 'pending', 'stopping', 'stopped']},
    ]
    for instance in ec2.instances.filter(Filters=cloudformation_filter):
        oddstack = cf.Stack(get_tag(instance.tags, 'aws:cloudformation:stack-name'))
        oddstack.delete()
        waiter = cfc.get_waiter('stack_delete_complete')
        with ActionOnExit('Waiting of Stack delete') as act:
            try:
                waiter.wait(StackName=get_tag(instance.tags, 'aws:cloudformation:stack-name'))
            except botocore.exceptions.WaiterError as e:
                act.error('Stack delete failed: {}'.format(e))
