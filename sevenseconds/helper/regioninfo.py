import boto3


def get_regions(servicename: str):
    return boto3.session.Session().get_available_regions(servicename)
