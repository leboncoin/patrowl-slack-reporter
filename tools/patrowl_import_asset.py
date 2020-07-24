#!/usr/bin/env python
"""
Patrowl Import Asset

Copyright 2020 Leboncoin
Licensed under the Apache License
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import logging
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Third party library imports
# from patrowl4py.api import PatrowlManagerApi
from patrowl4py.api import PatrowlManagerApi
from patrowl4py.exceptions import PatrowlException

# Own libraries
import settings

# Debug
# from pdb import set_trace as st

VERSION = '1.0.2'

PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

WARNINGS_TYPE_BLACKLIST = []

LOGGER = logging.getLogger('patrowl-import-asset')

ASSET = sys.argv[1]

def get_assets():
    """
    Get assets
    """
    try:
        return PATROWL_API.get_assets()
    except:
        return list()

def add_in_assetgroup(assetgroup_id, asset_id):
    """
    Main function
    """
    new_assets_ids = list()
    new_assets_ids.append(asset_id)

    dst_assetgroup = PATROWL_API.get_assetgroup_by_id(assetgroup_id)
    for current_asset in dst_assetgroup['assets']:
        new_assets_ids.append(current_asset['id'])
    PATROWL_API.edit_assetgroup(assetgroup_id, dst_assetgroup['name'], dst_assetgroup['description'], dst_assetgroup['criticity'], new_assets_ids)

def add_finding(asset, title, criticity):
    try:
        PATROWL_API.add_finding(
            title,
            title,
            'patrowl_threat_tagger',
            criticity,
            asset['id'])
    except PatrowlException:
        pass

def main():
    asset = dict()
    try:
        asset = PATROWL_API.add_asset(ASSET, ASSET, 'domain', ASSET, 'medium', tags=["All"])
    except PatrowlException as err_msg:
        if ' already exists.' in err_msg.args[0]:
            LOGGER.critical('%s already exists.', ASSET)
        else:
            LOGGER.critical('Unable to create asset')

    if not asset:
        asset = [a for a in get_assets() if a['value'] == ASSET]
        if not isinstance(asset, list) or not asset:
            LOGGER.critical('asset not found in Patrowl')
            return 1
        asset = asset[0]
    else:
        LOGGER.info('Create asset %s: #%s', ASSET, asset['id'])
        add_in_assetgroup(settings.ASSETGROUP_ID, asset['id'])
        LOGGER.info('Add asset %s in assetgroup %s', ASSET, settings.ASSETGROUP_ID)

    result = input('Do you want to add a finding ? [y/n] ')
    if result.lower() != 'y':
        return 0
    threat_codename = input('Threat codename: ')
    criticity = input('Criticity: ')
    if criticity in ['high', 'medium', 'low']:
        add_finding(asset, 'Threat codename: '+threat_codename+' (0.0.0.0)', criticity)
        LOGGER.info('Add finding: Threat codename: %s (0.0.0.0), Criticity %s', threat_codename, criticity)
    else:
        LOGGER.warning('Criticity not valid...')
    return 0

if __name__ == '__main__':
    EXIT_CODE = main()
    sys.exit(EXIT_CODE)
