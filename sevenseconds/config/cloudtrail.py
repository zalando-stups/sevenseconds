from ..helper import ActionOnExit, info
from ..helper.regioninfo import get_regions
from ..helper.threading import ThreadWorker, Queue
import sevenseconds.helper

DEFAULT_CLOUDTRAIL_REGION = 'eu-west-1'

# TODO write a helper for update Cloudtrail S3 Policy
# get IDs from http://docs.aws.amazon.com/general/latest/gr/rande.html#ct_region and update the Policy


def configure_cloudtrail_all_regions(account: object):
    if 'cloudtrail' not in account.config:
        info('Found no Cloudtrail Section in Configfile. Skipping CloudTrail configuration')
        return
    configure_cloudtrail(account)
    drop_old_cloudtrails(account)


def drop_old_cloudtrails(account):

    # boto3 doesn't support regioninfo.get_regions from boto
    # for region in boto.regioninfo.get_regions('cloudtrail'):
    #    configure_cloudtrail(session, region.name, cfg, dry_run)
    home_region = account.config['cloudtrail'].get('home_region', DEFAULT_CLOUDTRAIL_REGION)
    regions = get_regions('cloudtrail')
    if home_region in regions:
        regions.remove(home_region)
    # Create a queue to communicate with the worker threads
    queue = Queue()
    # Create X worker threads
    for x in range(len(regions)):
        worker = ThreadWorker(queue, drop_old_cloudtrails_worker)
        # Setting daemon to True will let the main thread exit even though the workers are blocking
        worker.daemon = True
        worker.start()
    # Put the tasks into the queue as a tuple
    for region in regions:
        queue.put((account, region, account.dry_run))
    queue.join()


def drop_old_cloudtrails_worker(account, region, dry_run):
    sevenseconds.helper.THREADDATA.name = '{}|{}'.format(account.name, region)
    with ActionOnExit('search for old CloudTrail configuration in Region: {}'.format(region)) as act:
        cloudtrail = account.session.client('cloudtrail', region)
        trails = cloudtrail.describe_trails(includeShadowTrails=False)['trailList']
        if trails:
            act.error('found existing config')
        else:
            return

    for trail in trails:
        delname = trail.get('Name')
        with ActionOnExit('[{}] Deleting old trail {}..'.format(region, delname)):
            if not dry_run:
                cloudtrail.stop_logging(Name=delname)
                cloudtrail.delete_trail(Name=delname)


def configure_cloudtrail(account: object):
    if 'cloudtrail' not in account.config:
        return
    region = account.config['cloudtrail'].get('home_region', DEFAULT_CLOUDTRAIL_REGION)
    cloudtrail = account.session.client('cloudtrail', region)
    trails = cloudtrail.describe_trails()['trailList']
    name = 'Default'
    trail = find_trail(trails, name)
    kwargs = dict(Name=name,
                  S3BucketName=account.config['cloudtrail']['s3_bucket_name'],
                  S3KeyPrefix=account.config['cloudtrail']['s3_key_prefix'],
                  IsMultiRegionTrail=True,
                  IncludeGlobalServiceEvents=True)
    if trail:
        with ActionOnExit('Checking CloudTrail in region {}..'.format(region)) as act:
            if not account.dry_run:
                if (trail['IncludeGlobalServiceEvents'] != kwargs['IncludeGlobalServiceEvents'] or
                        trail.get('S3KeyPrefix', '') != kwargs['S3KeyPrefix'] or
                        trail['S3BucketName'] != kwargs['S3BucketName'] or
                        trail['IsMultiRegionTrail'] != kwargs['IsMultiRegionTrail']):
                    act.error('wrong configuration')
                    cloudtrail.update_trail(**kwargs)
                status = cloudtrail.get_trail_status(Name=name)
                if not status['IsLogging']:
                    act.error('was not active')
                    cloudtrail.start_logging(Name=name)
    else:
        if trails:
            for trail in trails:
                delname = trail.get('Name')
                with ActionOnExit('[{}] Deleting invalid trail {} in region {}..'
                                  .format(account.name, delname, region)):
                    if not account.dry_run:
                        cloudtrail.stop_logging(Name=delname)
                        cloudtrail.delete_trail(Name=delname)
        with ActionOnExit('[{}] Enabling CloudTrail..'.format(region)):
            if not account.dry_run:
                cloudtrail.create_trail(**kwargs)
                cloudtrail.start_logging(Name=name)


def find_trail(trails: list, name):
    for trail in trails:
        if trail.get('Name') == name:
            return trail
