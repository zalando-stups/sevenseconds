def configure_log_group(session: object, region: str):
    client = session.client('logs', region)
    logs = client.describe_log_groups(logGroupNamePrefix='vpc-flowgroup')['logGroups']
    for log in logs:
        if log.get('logGroupName', '') == 'vpc-flowgroup':
            return
    client.create_log_group(logGroupName='vpc-flowgroup')
