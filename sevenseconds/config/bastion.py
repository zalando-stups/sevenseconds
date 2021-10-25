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
from .route53 import configure_dns_record, delete_dns_record
from ..config import AccountData


def configure_bastion_host(account: AccountData, vpc: object, region: str, base_ami_id: str):
    ec2 = account.session.resource('ec2', region)
    cf = account.session.resource('cloudformation', region)
    cfc = account.session.client('cloudformation', region)

    enable_bastion = account.config.get("enable_odd", False)
    re_deploy = account.config['bastion'].get('re_deploy', account.options.get('redeploy_odd_host'))

    if not base_ami_id:
        enable_bastion = False

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
            if instance.image_id != base_ami_id:
                error('{} use {} instand of {}.'.format(instance.id, instance.image_id, base_ami_id))
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
        if not enable_bastion:
            info('bastion not enabled and instances found. Start clean up')
            delete_bastion_host(account, region)
            return
        for instance in cloudformation_instances:
            # Terminate old (stopped) Odd Systems
            if instance.state.get('Name') == 'stopped':
                drop_bastionhost(instance)
            else:
                # Verify Running Version (Userdate, FS Parameter)
                oddstack = cf.Stack(get_tag(instance.tags, 'aws:cloudformation:stack-name'))

                used_ami_id = get_tag(oddstack.parameters, 'TaupageId', prefix='Parameter')
                if used_ami_id != base_ami_id:
                    error('{} use {} instand of {}.'.format(oddstack.name, used_ami_id, base_ami_id))
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
                    update_cf_bastion_host(account, vpc, region, oddstack, base_ami_id, bastion_version)
                if not legacy_instances:
                    info('check old odd security groups')
                    cleanup_old_security_group(account, region, oddstack, vpc)

    if not legacy_instances and not cloudformation_instances and enable_bastion:
        try:
            stack = cf.Stack('Odd')
            info('Stack Status: {}'.format(stack.stack_status))
        except Exception:
            create_cf_bastion_host(account, vpc, region, base_ami_id, bastion_version)
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
            update_cf_bastion_host(account, vpc, region, stack, base_ami_id, bastion_version)


def cleanup_old_security_group(account: AccountData, region: str, oddstack: object, vpc: object):
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


def create_cf_bastion_host(account: AccountData, vpc: object, region: str, ami_id: str, bastion_version: str):
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
            {'Key': 'LastUpdate', 'Value': time.strftime('%Y-%m-%dT%H:%M:%S%z')},
            {'Key': 'InfrastructureComponent', 'Value': 'true'}
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
    if account.domain is not None:
        configure_dns_record(account, 'odd-{}'.format(region), ip)
    else:
        warning('No DNS domain configured, skipping record creation')


def update_cf_bastion_host(account: AccountData, vpc: object, region: str, stack: object, ami_id: str,
                           bastion_version: str):
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
            {'Key': 'LastUpdate', 'Value': time.strftime('%Y-%m-%dT%H:%M:%S%z')},
            {'Key': 'InfrastructureComponent', 'Value': 'true'}
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
            except Exception:
                result = -1
            if result == 0:
                return True
            if time.time() - start > timeout:
                act.error('TIMEOUT')
                return False
            time.sleep(5)
            act.progress()


def delete_bastion_host(account: AccountData, region: str):
    ec2 = account.session.resource('ec2', region)
    cf = account.session.resource('cloudformation', region)
    cfc = account.session.client('cloudformation', region)

    for instance in ec2.instances.all():
        if get_tag(instance.tags, 'Name') == 'Odd (SSH Bastion Host)':
            if instance.state.get('Name') in ('running', 'pending', 'stopping', 'stopped'):
                if account.domain is not None and instance.public_ip_address:
                    try:
                        delete_dns_record(account, 'odd-{}'.format(region), instance.public_ip_address)
                    except Exception:
                        pass
                drop_bastionhost(instance)

    cloudformation_filter = [
        {'Name': 'tag:aws:cloudformation:logical-id',
         'Values': ['OddServerInstance']},
        {'Name': 'instance-state-name',
         'Values': ['running', 'pending', 'stopping', 'stopped']},
    ]
    for instance in ec2.instances.filter(Filters=cloudformation_filter):
        if account.domain is not None and instance.public_ip_address:
            try:
                delete_dns_record(account, 'odd-{}'.format(region), instance.public_ip_address)
            except Exception as e:
                warning('Can\'t cleanup old Odd host name: {}'.format(e))
        oddstack = cf.Stack(get_tag(instance.tags, 'aws:cloudformation:stack-name'))
        oddstack.delete()
        waiter = cfc.get_waiter('stack_delete_complete')
        with ActionOnExit('Waiting of Stack delete') as act:
            try:
                waiter.wait(StackName=get_tag(instance.tags, 'aws:cloudformation:stack-name'))
            except botocore.exceptions.WaiterError as e:
                act.error('Stack delete failed: {}'.format(e))
