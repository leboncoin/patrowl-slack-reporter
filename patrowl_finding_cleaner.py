#!/usr/bin/env python
"""
Patrowl Finding Cleaner

Copyright 2020 Leboncoin
Licensed under the Apache License
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""


# Standard library imports
import logging
import sys

# Third party library imports
from patrowl4py.api import PatrowlManagerApi
import urllib3

# Own libraries
import settings

# Debug
# from pdb import set_trace as st

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = '1.1.2'

logging.basicConfig()
LOGGER = logging.getLogger('patrowl-finding-cleaner')
PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

MULTIPLE_THRESHOLD = {
    # Eyewitness
    'eyewitness_screenshot': 3,
    'eyewitness_screenshot_diff': 1,
    # Virustotal
    # 'vt_url_positivematch': 1,
    'domain_categories': 1,
    'domain_detected_referrer_samples': 1,
    'domain_detected_urls': 1,
    'domain_report': 2,
    'domain_resolutions': 2,
    'domain_siblings': 1,
    'domain_undetected_referrer_samples': 1,
    'domain_webutation_info': 1,
    'domain_webutation_verdict': 1,
    'domain_whois': 2,
    'ip_detected_samples': 1,
    'ip_undetected_samples': 1,
    'subdomain_list': 1,
    # Certstream
    'certstream_report': 1,
}

DUPLICATE_LIST = [
    'Current IP',
    'Domain for sale',
    'Threat codename',
]

def delete_finding(finding_id, test_only=False):
    """
    This function is a wrapper around PATROWL_API.delete_finding
    """
    if test_only:
        LOGGER.warning('[TEST-ONLY] Delete finding.')
        return
    try:
        PATROWL_API.delete_finding(
            finding_id)
    except:
        LOGGER.critical('Error during delete finding #%s', finding_id)
        pass

def clean_multiples(findings, test_only=False):
    """
    Remove multiple findings
    """
    multiples = dict()
    for finding_type in MULTIPLE_THRESHOLD:
        multiples[finding_type] = list()

    for finding in findings:
        if 'type' in finding and finding['type'] in multiples:
            multiples[finding['type']].append(finding['id'])

    for finding_type in MULTIPLE_THRESHOLD:
        multiples[finding_type].sort()
        if len(multiples[finding_type]) > MULTIPLE_THRESHOLD[finding_type]:
            for old_finding in multiples[finding_type][:-MULTIPLE_THRESHOLD[finding_type]]:
                LOGGER.warning('Remove old %s #%s', finding_type, old_finding)
                delete_finding(old_finding, test_only=test_only)

def clean_duplicates(findings, test_only=False):
    """
    Remove duplicate findings
    """
    duplicates = dict()
    for finding_title in DUPLICATE_LIST:
        duplicates[finding_title] = list()

    for finding in findings:
        for finding_title in DUPLICATE_LIST:
            if 'title' in finding and finding_title in finding['title']:
                duplicates[finding_title].append(finding['id'])

    for finding_title in DUPLICATE_LIST:
        duplicates[finding_title].sort()
        if len(duplicates[finding_title]) > 1:
            for old_finding in duplicates[finding_title][:-1]:
                LOGGER.warning('Remove duplicate %s #%s', finding_title, old_finding)
                delete_finding(old_finding, test_only=test_only)

def main(test_only=False):
    """
    Main function
    """
    assets = PATROWL_API.get_assets()
    for asset in assets:
        try:
            findings = PATROWL_API.get_asset_findings_by_id(asset['id'])
        except:
            LOGGER.critical('Cannot get findings for asset #%s', asset['id'])
            continue
        clean_multiples(findings, test_only=test_only)
        clean_duplicates(findings, test_only=test_only)

if __name__ == '__main__':
    DEBUG = len(sys.argv) > 1 and sys.argv[1] == '--test-only'
    main(test_only=DEBUG)
