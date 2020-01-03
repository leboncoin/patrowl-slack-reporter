#!/usr/bin/env python
#-*- coding: utf-8 -*-
""" Patrowl Asset Lifecycle """

# Standard library imports
from datetime import datetime
import json
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Third party library imports
from dateutil.parser import parse
# from patrowl4py.api import PatrowlManagerApi
from Patrowl4py.patrowl4py.api import PatrowlManagerApi
from pytz import timezone
from requests import Session

# Own libraries
import patrowl_asset_lifecycle_settings as settings

# Debug
# from pdb import set_trace as st

VERSION = '1.0.2'

PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

WARNINGS_TYPE_BLACKLIST = []

LOGGER = logging.getLogger('patrowl-asset-lifecycle')

SESSION = Session()

COLOR_MAPPING = {
    'info': '#b4c2bf',
    'low': '#4287f5',
    'medium': '#f5a742',
    'high': '#b32b2b',
}

NOW = datetime.now()
TZ = timezone(settings.TIMEZONE)
NOW = TZ.localize(NOW)
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

def has_recent_findings(asset, severities, days):
    """
    Returns the asset if recent findings
    """
    seconds = days*12*3600
    for finding in PATROWL_API.get_asset_findings_by_id(asset['id']):
        found_at = TZ.localize(parse(finding['found_at']).replace(tzinfo=None))
        diff = (NOW - found_at).total_seconds()
        if diff <= seconds \
            and finding['severity'] in severities \
            and finding['type'] not in WARNINGS_TYPE_BLACKLIST:
            return True
    return False

def has_old_findings(asset, severities, days):
    """
    Returns the asset if recent findings
    """
    seconds = days*12*3600
    has_severe_findings = False
    has_a_recent_finding = False
    for finding in PATROWL_API.get_asset_findings_by_id(asset['id']):
        found_at = TZ.localize(parse(finding['found_at']).replace(tzinfo=None))
        diff = (NOW - found_at).total_seconds()
        if finding['severity'] in severities \
            and finding['type'] not in WARNINGS_TYPE_BLACKLIST:
            has_severe_findings = True
            if diff <= seconds:
                has_a_recent_finding = True
    return has_severe_findings and not has_a_recent_finding

def slack_alert(asset, asset_type, asset_destination, criticity='high'):
    """
    Post report on Slack
    """
    payload = dict()
    payload['channel'] = settings.SLACK_CHANNEL
    payload['link_names'] = 1
    payload['username'] = settings.SLACK_USERNAME
    payload['icon_emoji'] = settings.SLACK_ICON_EMOJI

    attachments = dict()
    attachments['pretext'] = '{} threat move to {}'.format(asset_type, asset_destination)
    attachments['fields'] = []
    attachments['color'] = COLOR_MAPPING[criticity]

    attachments['text'] = safe_url(asset['name'])
    attachments['fields'].append({'title': 'Patrowl asset link', 'value': '{}/assets/details/{}'.format(settings.PATROWL_PUBLIC_ENDPOINT, asset['id'])})

    payload['attachments'] = [attachments]

    response = SESSION.post(settings.SLACK_WEBHOOK, data=json.dumps(payload))

    return response.ok

def move_asset(asset, src_group_id, src_group_name, dst_group_id, dst_group_name):
    """
    This function moves assets from one assetgroup to another
    """
    if dst_group_id is None:
        PATROWL_API.add_assetgroup(
            dst_group_name,
            dst_group_name,
            'high',
            [asset['id']])
    else:
        # Add asset in new assetgroup
        new_assets = [asset['id']]
        for current_asset in PATROWL_API.get_assetgroup_by_id(dst_group_id)['assets']:
            new_assets.append(current_asset['id'])
        PATROWL_API.edit_assetgroup(dst_group_id, dst_group_name, dst_group_name, 'medium', new_assets)

    # Remove asset from old assetgroup
    new_assets = list()
    for current_asset in PATROWL_API.get_assetgroup_by_id(src_group_id)['assets']:
        if current_asset['id'] != asset['id']:
            new_assets.append(current_asset['id'])
    PATROWL_API.edit_assetgroup(src_group_id, src_group_name, src_group_name, 'medium', new_assets)

def main():
    """
    Main function
    """
    current_threats_group_id, archived_threats_group_id = get_group_ids()

    base_assets = get_assets(settings.GROUP_ID)
    ct_assets = list()
    if current_threats_group_id is not None:
        ct_assets = get_assets(current_threats_group_id)
    at_assets = list()
    if archived_threats_group_id is not None:
        at_assets = get_assets(archived_threats_group_id)

    if not base_assets and not ct_assets and not at_assets:
        LOGGER.warning('no assets')
    else:
        for base_asset in base_assets:
            if has_recent_findings(base_asset, 'high', settings.MAX_DAYS):
                resp_ok = slack_alert(base_asset, 'New', '{} current threats'.format(ASSETGROUP_BASE_NAME))
                if not resp_ok:
                    continue
                LOGGER.warning('move asset {} from {} to {}'.format(base_asset, ASSETGROUP_BASE_NAME, '{} current threats'.format(ASSETGROUP_BASE_NAME)))
                move_asset(
                    base_asset,
                    settings.GROUP_ID,
                    ASSETGROUP_BASE_NAME,
                    current_threats_group_id,
                    '{} current threats'.format(ASSETGROUP_BASE_NAME))
                if current_threats_group_id is None:
                    current_threats_group_id, _ = get_group_ids()
            elif has_old_findings(base_asset, 'high', settings.MAX_DAYS):
                resp_ok = slack_alert(base_asset, 'New', '{} archived threats'.format(ASSETGROUP_BASE_NAME), criticity='low')
                if not resp_ok:
                    continue
                LOGGER.warning('move asset {} from {} to {}'.format(base_asset, ASSETGROUP_BASE_NAME, '{} archived threats'.format(ASSETGROUP_BASE_NAME)))
                move_asset(
                    base_asset,
                    settings.GROUP_ID,
                    ASSETGROUP_BASE_NAME,
                    archived_threats_group_id,
                    '{} archived threats'.format(ASSETGROUP_BASE_NAME))
                if archived_threats_group_id is None:
                    _, archived_threats_group_id = get_group_ids()
        if at_assets:
            for archived_asset in at_assets:
                if not has_recent_findings(archived_asset, 'high', settings.MAX_DAYS):
                    continue
                resp_ok = slack_alert(archived_asset, 'Archived', '{} current threats'.format(ASSETGROUP_BASE_NAME))
                if not resp_ok:
                    continue
                LOGGER.warning('move asset {} from {} to {}'.format(archived_asset, '{} archived threats'.format(ASSETGROUP_BASE_NAME), '{} current threats'.format(ASSETGROUP_BASE_NAME)))
                move_asset(
                    archived_asset,
                    archived_threats_group_id,
                    '{} archived threats'.format(ASSETGROUP_BASE_NAME),
                    current_threats_group_id,
                    '{} current threats'.format(ASSETGROUP_BASE_NAME))
                if current_threats_group_id is None:
                    current_threats_group_id, _ = get_group_ids()
        if ct_assets:
            for threat_asset in ct_assets:
                if not has_recent_findings(threat_asset, 'high', settings.MAX_DAYS):
                    continue
                resp_ok = slack_alert(threat_asset, 'Current', '{} archived threats'.format(ASSETGROUP_BASE_NAME), criticity='low')
                if not resp_ok:
                    continue
                LOGGER.warning('move asset {} from {} to {}'.format(threat_asset, '{} current threats'.format(ASSETGROUP_BASE_NAME), '{} archived threats'.format(ASSETGROUP_BASE_NAME)))
                move_asset(
                    threat_asset,
                    current_threats_group_id,
                    '{} current threats'.format(ASSETGROUP_BASE_NAME),
                    archived_threats_group_id,
                    '{} archived threats'.format(ASSETGROUP_BASE_NAME))
                if archived_threats_group_id is None:
                    _, archived_threats_group_id = get_group_ids()

if __name__ == '__main__':
    main()
