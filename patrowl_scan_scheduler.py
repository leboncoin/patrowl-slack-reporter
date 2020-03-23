#!/usr/bin/env python
"""
Patrowl Scan Scheduler

Copyright (c) 2020 Nicolas Beguier
Licensed under the Apache License
Written by Nicolas BEGUIER (nicolas_beguier@hotmail.com)
"""

# Standard library imports
from datetime import datetime, timedelta
import logging
import re
import urllib

# Third party library imports
from dateutil.parser import parse
import urllib3
from patrowl4py.api import PatrowlManagerApi

# Own libraries
import settings

# Debug
# from pdb import set_trace as st

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = '1.0.5'

PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

logging.basicConfig()
LOGGER = logging.getLogger('patrowl-scan-scheduler')

def get_period_from_title(title):
    """
    Returns the period from the title.
    Looking for [<period>]:
      - Every n minutes, Every n hours, Hourly, Daily
    """
    # pylint: disable=W1401
    for tag in re.findall("\[(.*?)\]", title):
        if tag == 'Daily':
            return timedelta(days=1)
        if tag == 'Hourly':
            return timedelta(hours=1)
        if tag.startswith('Every '):
            try:
                duration = int(tag.split()[1])
            except ValueError:
                return None
            period_type = tag.split()[2]
            if period_type == 'hours':
                return timedelta(hours=duration)
            if period_type == 'minutes':
                return timedelta(minutes=duration)
    return None

def do_scan(scan_def):
    """
    Retuns True if the scan definition is scannable
    """
    if scan_def['scan_type'] != 'single' or not scan_def['title'].startswith('[PSS]'):
        return False

    period = get_period_from_title(scan_def['title'])

    if period is None:
        LOGGER.warning('Error parsing scan definition #%s: period not found in tags', scan_def['id'])
        return False

    for scan in PATROWL_API.get_scans(title=urllib.parse.quote(scan_def['title'])):
        if scan['status'] in ['enqueued', 'started']:
            LOGGER.warning('scan definition #%s already %s', scan_def['id'], scan['status'])
            return False

    last_scans = PATROWL_API.get_scans(status='finished', title=urllib.parse.quote(scan_def['title']))
    # In case there is no finished scan
    if not last_scans:
        return True

    # Get last finished scan
    last_scan_date = parse(last_scans[0]['finished_at'])
    for last_scan in last_scans:
        if parse(last_scan['finished_at']) > last_scan_date:
            last_scan_date = parse(last_scan['finished_at'])

    now = datetime.now(tz=last_scan_date.tzinfo)

    if (now - last_scan_date) < period:
        LOGGER.warning('scan definition #%s has run recently: %s', scan_def['id'], now - last_scan_date)
        return False

    return True


def main():
    """
    Main function
    """
    for scan_def in PATROWL_API.get_scan_definitions():
        if do_scan(scan_def):
            result = PATROWL_API.run_scan_definitions(scan_def['id'])
            if result != {'status': 'success'}:
                LOGGER.critical('Error running scan definition #%s: %s', scan_def['id'], result)
            else:
                LOGGER.warning('Scan definition #%s is starting', scan_def['id'])

if __name__ == '__main__':
    main()
