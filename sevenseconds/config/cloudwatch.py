def configure_log_group(session: object, region: str, config: dict):
    retention_in_days = config.get("vpc", {}).get("flow_logs_retention_in_days", 3653)
    client = session.client("logs", region)
    logs = client.describe_log_groups(logGroupNamePrefix="vpc-flowgroup")["logGroups"]
    for log in logs:
        if log.get("logGroupName", "") == "vpc-flowgroup":
            if log.get("retentionInDays", 0) != retention_in_days:
                client.put_retention_policy(
                    logGroupName="vpc-flowgroup",
                    retentionInDays=retention_in_days,
                )
            return
    client.create_log_group(logGroupName="vpc-flowgroup")
    client.put_retention_policy(
        logGroupName="vpc-flowgroup",
        retentionInDays=retention_in_days,
    )
