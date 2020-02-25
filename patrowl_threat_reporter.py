#!/usr/bin/env python
"""
Patrowl Threat Reporter

Copyright (c) 2020 Nicolas Beguier
Licensed under the Apache License
Written by Nicolas BEGUIER (nicolas_beguier@hotmail.com)
"""

# Standard library imports
import json
import logging
import re

# Third party library imports
from patrowl4py.api import PatrowlManagerApi
# from Patrowl4py.patrowl4py.api import PatrowlManagerApi
from requests import Session
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Own libraries
import patrowl_threat_reporter_settings as settings

# Debug
# from pdb import set_trace as st

VERSION = '1.0.0'

PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

LOGGER = logging.getLogger('patrowl-threat-reporter')

SESSION = Session()

COLOR_MAPPING = {
    'info': '#b4c2bf',
    'low': '#4287f5',
    'medium': '#f5a742',
    'high': '#b32b2b',
}

ASSETGROUP_BASE_NAME = PATROWL_API.get_assetgroup_by_id(settings.GROUP_ID)['name']

def safe_url(text):
    """
    Returns a safe unclickable link
    """
    return text.replace('http:', 'hxxp:').replace('https:', 'hxxps:').replace('.', '[.]')

def get_group_ids():
    """
    Get group IDs of current threats and archived threats.
    """
    current_threats_group_id = None
    archived_threats_group_id = None
    for assetgroup in PATROWL_API.get_assetgroups():
        if assetgroup['name'] == '{} current threats'.format(ASSETGROUP_BASE_NAME):
            current_threats_group_id = assetgroup['id']
        elif assetgroup['name'] == '{} archived threats'.format(ASSETGROUP_BASE_NAME):
            archived_threats_group_id = assetgroup['id']
    return current_threats_group_id, archived_threats_group_id

def get_assets(assetgroup_id):
    """
    Get assets from base AssetGroup
    """
    assets_list = []
    assets = list()
    assetgroup = PATROWL_API.get_assetgroup_by_id(assetgroup_id)
    assets += sorted(assetgroup['assets'], key=lambda k: k['id'], reverse=True)
    for asset in assets:
        assets_list.append(asset)

    return assets_list


def get_findings(assets):
    """
    Returns the list of findings matchins
      - 'Current IP: xx.xx.xx.xx'
      - 'Threat codename: xxxx (xx.xx.xx.xx)'
    """
    assets_findings = dict()
    for asset in assets:
        assets_findings[asset['id']] = list()
        for finding in PATROWL_API.get_asset_findings_by_id(asset['id']):
            if 'Current IP: ' in finding['title'] \
                or 'Threat codename: ' in finding['title']:
                assets_findings[asset['id']].append(finding)
    return assets_findings


def slack_alert(threats):
    """
    Post report on Slack
    """
    payload = dict()
    payload['channel'] = settings.SLACK_CHANNEL
    payload['link_names'] = 1
    payload['username'] = settings.SLACK_USERNAME
    payload['icon_emoji'] = settings.SLACK_ICON_EMOJI

    attachments = dict()
    attachments['pretext'] = 'Patrowl Threat Reporter'
    attachments['fields'] = []
    attachments['color'] = COLOR_MAPPING['info']

    for codename in threats:
        attachments['fields'].append({
            'title': 'Threat codename: {}'.format(codename),
            'value': safe_url(str(threats[codename]['assets'])).
                     replace("['", '').
                     replace("']", '').
                     replace("',", ',').
                     replace(" '", ' ')
        })

    payload['attachments'] = [attachments]

    response = SESSION.post(settings.SLACK_WEBHOOK, data=json.dumps(payload))

    return response.ok


def main():
    """
    Main function
    """
    current_threats_group_id, archived_threats_group_id = get_group_ids()

    base_assets = get_assets(settings.GROUP_ID)
    if current_threats_group_id is None or archived_threats_group_id is None:
        LOGGER.critical('run Patrowl Asset Lifecycle first')
        exit(1)
    ct_assets = get_assets(current_threats_group_id)
    at_assets = get_assets(archived_threats_group_id)

    if not base_assets and not ct_assets and not at_assets:
        LOGGER.warning('no assets')
    else:
        threats = dict()
        ct_findings = get_findings(ct_assets)
        for asset_id in ct_findings:
            for finding in ct_findings[asset_id]:
                if 'Threat codename: ' in finding['title'] \
                    and finding['severity'] == 'high':
                    match = re.search(re.compile('Threat codename: (.*) \('), finding['title'])
                    if match:
                        if match.group(1) not in threats:
                            threats[match.group(1)] = dict()
                            threats[match.group(1)]['assets'] = list()
                            threats[match.group(1)]['severity'] = finding['severity']
                            threats[match.group(1)]['found_at'] = finding['found_at']
                        threats[match.group(1)]['assets'].append(finding['asset_name'])

        slack_alert(threats)

if __name__ == '__main__':
    main()
