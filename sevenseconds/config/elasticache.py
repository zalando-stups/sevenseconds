from ..helper import ActionOnExit
from ..helper.aws import filter_subnets


def configure_elasticache(session, region, vpc):
    client = session.client('elasticache', region)
    subnet_ids = [sn.id for sn in filter_subnets(vpc, 'internal')]
    try:
        response = client.describe_cache_subnet_groups(
            CacheSubnetGroupName='internal',
        )['CacheSubnetGroups'][0]

        if response['VpcId'] != vpc.id:
            with ActionOnExit('Remove ElastiCache subnet group..'):
                client.delete_cache_subnet_group(CacheSubnetGroupName='internal')
            # go to except
            raise
        elif set(subnet_ids) != set([x['SubnetIdentifier'] for x in response['Subnets']]):
            with ActionOnExit('Replacing ElastiCache subnet group..'):
                client.modify_cache_subnet_group(
                    CacheSubnetGroupName='internal',
                    CacheSubnetGroupDescription='Default subnet group using all internal subnets',
                    SubnetIds=subnet_ids
                )
    except:
        with ActionOnExit('Creating ElastiCache subnet group..') as act:
            try:
                client.create_cache_subnet_group(
                    CacheSubnetGroupName='internal',
                    CacheSubnetGroupDescription='Default subnet group using all internal subnets',
                    SubnetIds=subnet_ids
                )
            except Exception as e:
                act.error(e)
