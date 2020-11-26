#!/usr/bin/env python
"""
Patrowl Scan Cleaner

Copyright 2020 Leboncoin
Licensed under the Apache License
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
from datetime import datetime
import logging
import sys
import urllib
import urllib3

# Third party library imports
from dateutil.parser import parse
from patrowl4py.api import PatrowlManagerApi
from patrowl4py.exceptions import PatrowlException

# Own libraries
import settings

# Debug
# from pdb import set_trace as st

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = '1.0.0'

PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

LOGGER = logging.getLogger('patrowl-delete-old-scans')

def days_old(scan):
    """
    Returns True if the scan finished date is inferior at "days"
    """
    if scan['finished_at'] is None:
        return 0
    scan_date = parse(scan['finished_at'])
    now = datetime.now(tz=scan_date.tzinfo)
    delta = (now - scan_date).days
    return delta

def clean_scan_def(scan_def_id, days, batch=50, auto=False):
    """
    clean_scan_def function
    """
    try:
        scan_def = PATROWL_API.get_scan_definition_by_id(scan_def_id)
    except PatrowlException:
        LOGGER.critical('Unable to get scan definition #%s', scan_def_id)
        return 1
    LOGGER.warning('Title: %s', scan_def['title'])
    LOGGER.warning('Enabled: %s', scan_def['enabled'])
    if scan_def['scan_type'] == 'periodic':
        LOGGER.warning('Periodic: every %s %s', scan_def['every'], scan_def['period'])
    else:
        LOGGER.warning(scan_def['scan_type'])

    if not auto:
        result = input('Do you want to delete old scans of this scan def ? [Y/n] ')
        if result.lower() == 'n':
            return 0

    try:
        scans = PATROWL_API.get_scans(title=urllib.parse.quote(scan_def['title']), limit=batch)
    except PatrowlException:
        LOGGER.critical('Error while getting scans')
        return 1
    at_least_one_change = True
    while scans and at_least_one_change:
        at_least_one_change = False
        for scan in scans:
            if str(scan['scan_definition']) != scan_def_id:
                LOGGER.warning('Scan not in scan def, pass..')
                continue
            scan_days = days_old(scan)
            if scan_days < days:
                continue
            try:
                PATROWL_API.delete_scan_by_id(scan['id'])
                LOGGER.warning(
                    'Successfully removed scan #%s, %s days old',
                    scan['id'],
                    scan_days)
                at_least_one_change = True
            except PatrowlException:
                LOGGER.critical('Error when removing scan #%s', scan['id'])
        try:
            scans = PATROWL_API.get_scans(title=urllib.parse.quote(scan_def['title']), limit=batch)
        except PatrowlException:
            LOGGER.critical('Error while getting scans')
            return 1

    LOGGER.warning('Finished')
    return 0

if __name__ == '__main__':
    if len(sys.argv) < 2:
        LOGGER.critical('You need to specify a scan definition (or a list separated by comma) ID, days')
        LOGGER.critical("$ %s SCAN_DEF_IDS DAYS", sys.argv[0])
        sys.exit(1)
    SCAN_DEF_IDS = sys.argv[1].split(',')
    DAYS = int(sys.argv[2])
    for scan_def_id in SCAN_DEF_IDS:
        clean_scan_def(scan_def_id, DAYS, auto=False)
