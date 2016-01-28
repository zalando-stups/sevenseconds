import os
import yaml
import requests
import datetime
from bs4 import BeautifulSoup
from ..helper import CONFIG_DIR_PATH, fatal_error

ENDPOINTS_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'endpoints.yaml')
AWS_REGION_URL = 'http://docs.aws.amazon.com/general/latest/gr/rande.html'
ENDPOINTS = {}


def init():
    if ENDPOINTS.get('_Last-Modified') is None:
        read_endpoints_from_file()
        if ENDPOINTS.get('_Last-Modified') is None:
            update_endpoints()
        else:
            # check only, if file older than 2 days
            timer = datetime.datetime.now() - datetime.timedelta(days=2)
            filemtime = datetime.datetime.fromtimestamp(os.path.getmtime(ENDPOINTS_FILE_PATH))
            if filemtime < timer:
                r = requests.head(AWS_REGION_URL, timeout=(3.05, 27), verify=True)
                if r.status_code == 200:
                    if r.headers.get('Last-Modified') != ENDPOINTS.get('_Last-Modified'):
                        update_endpoints()
                    else:
                        os.utime(ENDPOINTS_FILE_PATH, None)


def get_endpoints(servicename: str):
    return ENDPOINTS.get('endpoints').get(servicename, None)


def get_regions(servicename: str):
    return list(ENDPOINTS.get('endpoints').get(servicename, {}).keys())


def read_endpoints_from_file():
    try:
        ENDPOINTS.clear()
        with open(ENDPOINTS_FILE_PATH) as fd:
            ENDPOINTS.update(yaml.safe_load(fd))
    except:
        ENDPOINTS.clear()
    return ENDPOINTS or {}


def store_endpoints():
    dir_path = os.path.dirname(ENDPOINTS_FILE_PATH)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    with open(ENDPOINTS_FILE_PATH, 'w') as fd:
        yaml.safe_dump(ENDPOINTS, fd)


def update_endpoints():
    r = requests.get(AWS_REGION_URL, timeout=(3.05, 27), verify=True)
    if r.status_code != 200:
        fatal_error('unknown Status ({}): {}'.format(r.status_code, r.text))
    soup = BeautifulSoup(r.text, 'lxml')
    rande = soup.find(id='rande')
    endpoints = {}
    accountids = {}
    for service in rande.find_all(class_='section'):
        region_idx = endpoint_idx = accountid_idx = None
        parts = service.find(class_='title').get('id').replace('-', '_').split('_')
        servicename = '-'.join(parts[:-1])
        infotable = service.find('table')
        if (infotable):
            head = [th.text.strip() for th in infotable.find_all('th')]
            if 'Region' in head:
                region_idx = head.index('Region')
                if 'Endpoint' in head:
                    endpoints.setdefault(servicename, {})
                    endpoint_idx = head.index('Endpoint')
                if 'AWS Account ID' in head:
                    accountids.setdefault(servicename, {})
                    accountid_idx = head.index('AWS Account ID')
            for tr in infotable.find_all('tr'):
                data = [td.text.strip() for td in tr.find_all('td')]
                if data:
                    if endpoint_idx and region_idx:
                        # ignore second tables... (legacy Endpoints)
                        endpoints[servicename].setdefault(data[region_idx], data[endpoint_idx])
                        for endpoint in data[endpoint_idx].split('\n'):
                            if endpoint.endswith('amazonaws.com'):
                                servicename_long = endpoint.split('.')[0]
                                if (servicename_long.startswith('eu-') or
                                        servicename_long.startswith('us-') or
                                        servicename_long.startswith('ap-')):
                                    servicename_long = endpoint.split('.')[1]
                                if endpoints.get(servicename_long) is None:
                                    endpoints[servicename_long] = {}
                                # ignore second tables... (legacy Endpoints)
                                endpoints[servicename_long].setdefault(data[region_idx], endpoint)

                    if accountid_idx and region_idx:
                        accountids[servicename][data[region_idx]] = data[accountid_idx]
    ENDPOINTS['_Last-Modified'] = r.headers.get('Last-Modified')
    ENDPOINTS['accountids'] = accountids
    ENDPOINTS['endpoints'] = endpoints
    store_endpoints()


init()
