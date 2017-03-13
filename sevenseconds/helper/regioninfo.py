import os
import yaml
import requests
import datetime
from bs4 import BeautifulSoup
from ..helper import CONFIG_DIR_PATH, fatal_error
import boto3

def get_regions(servicename: str):
    return boto3.session.Session().get_available_regions(servicename)
