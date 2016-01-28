from ..helper import ActionOnExit
from ..helper.aws import filter_subnets


def configure_rds(session, region, vpc):
    client = session.client('rds', region)
    subnet_ids = [sn.id for sn in filter_subnets(vpc, 'internal')]
    try:
        response = client.describe_db_subnet_groups(
            DBSubnetGroupName='internal',
        )['DBSubnetGroups'][0]

        if response['VpcId'] != vpc.id:
            with ActionOnExit('Remove RDS subnet group..'):
                client.delete_db_subnet_group(DBSubnetGroupName='internal')
            # go to except
            raise
        elif set(subnet_ids) != set([x['SubnetIdentifier'] for x in response['Subnets']]):
            with ActionOnExit('Replacing RDS subnet group..'):
                client.modify_db_subnet_group(
                    DBSubnetGroupName='internal',
                    DBSubnetGroupDescription='Default subnet group using all internal subnets',
                    SubnetIds=subnet_ids
                )
    except:
        with ActionOnExit('Creating RDS subnet group..'):
            client.create_db_subnet_group(
                DBSubnetGroupName='internal',
                DBSubnetGroupDescription='Default subnet group using all internal subnets',
                SubnetIds=subnet_ids
            )
