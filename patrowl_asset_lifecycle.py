#!/usr/bin/env python
"""
Patrowl Asset Lifecycle

Copyright (c) 2020 Nicolas Beguier
Licensed under the Apache License
Written by Nicolas BEGUIER (nicolas_beguier@hotmail.com)
"""

# Standard library imports
from datetime import datetime
import json
import logging
import sys

# Third party library imports
from dateutil.parser import parse
from patrowl4py.api import PatrowlManagerApi
from pytz import timezone
from requests import Session
import urllib3

# Own libraries
import settings

# Debug
# from pdb import set_trace as st

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = '1.3.0'

PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

WARNINGS_TYPE_BLACKLIST = []

logging.basicConfig()
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
ASSETGROUP_BASE_NAME = PATROWL_API.get_assetgroup_by_id(settings.PAL_GROUP_ID)['name']

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
        if not 'found_at' in finding:
            continue
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

def current_ip_exists(asset):
    """
    Returns False if 'Current IP: No IP' finding exists
    """
    for finding in PATROWL_API.get_asset_findings_by_id(asset['id']):
        if finding['title'] == 'Current IP: No IP':
            return False
    return True

def domain_for_sale(asset):
    """
    Returns True if finding 'Domain for sale: True' exists
    """
    for finding in PATROWL_API.get_asset_findings_by_id(asset['id']):
        if finding['title'] == 'Domain for sale: True':
            return True
    return False

def slack_alert(asset, asset_type, asset_destination, criticity='high', test_only=False):
    """
    Post report on Slack
    """
    payload = dict()
    payload['channel'] = settings.SLACK_CHANNEL
    payload['link_names'] = 1
    payload['username'] = settings.PAL_SLACK_USERNAME
    payload['icon_emoji'] = settings.PAL_SLACK_ICON_EMOJI

    attachments = dict()
    attachments['pretext'] = '{} threat move to {}'.format(asset_type, asset_destination)
    attachments['fields'] = []
    attachments['color'] = COLOR_MAPPING[criticity]

    attachments['text'] = safe_url(asset['name'])
    attachments['fields'].append({'title': 'Patrowl asset link', 'value': '{}/assets/details/{}'.format(settings.PATROWL_PUBLIC_ENDPOINT, asset['id'])})

    payload['attachments'] = [attachments]

    if test_only:
        LOGGER.warning('[TEST-ONLY] Slack alert.')
        LOGGER.warning(payload)
        return True

    response = SESSION.post(settings.SLACK_WEBHOOK, data=json.dumps(payload))

    return response.ok

def move_asset(asset, src_group_id, src_group_name, dst_group_id, dst_group_name, test_only=False):
    """
    This function moves assets from one assetgroup to another
    """
    if test_only:
        LOGGER.warning('[TEST-ONLY] Move asset.')
        return
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
        try:
            PATROWL_API.edit_assetgroup(dst_group_id, dst_group_name, dst_group_name, 'medium', new_assets)
        except:
            LOGGER.critical('Error during edit_assetgroup %s', dst_group_name)

    # Remove asset from old assetgroup
    new_assets = list()
    for current_asset in PATROWL_API.get_assetgroup_by_id(src_group_id)['assets']:
        if current_asset['id'] != asset['id']:
            new_assets.append(current_asset['id'])
    try:
        PATROWL_API.edit_assetgroup(src_group_id, src_group_name, src_group_name, 'medium', new_assets)
    except:
        LOGGER.critical('Error during edit_assetgroup %s', src_group_name)


def base_asset_lifecycle(base_assets, archived_threats_group_id, current_threats_group_id, test_only=False):
    """
    Base asset handler
    """
    for base_asset in base_assets:
        # Base Asset: if "No IP" or "Domain for sale: True" => Archived Threat
        if not current_ip_exists(base_asset) or domain_for_sale(base_asset):
            resp_ok = slack_alert(base_asset, 'New', '{} archived threats'.format(ASSETGROUP_BASE_NAME), criticity='low', test_only=test_only)
            if not resp_ok:
                continue
            LOGGER.warning(
                'move asset %s from %s to %s',
                base_asset,
                ASSETGROUP_BASE_NAME,
                '{} archived threats'.format(ASSETGROUP_BASE_NAME))
            move_asset(
                base_asset,
                settings.PAL_GROUP_ID,
                ASSETGROUP_BASE_NAME,
                archived_threats_group_id,
                '{} archived threats'.format(ASSETGROUP_BASE_NAME),
                test_only=test_only)
            if archived_threats_group_id is None:
                _, archived_threats_group_id = get_group_ids()
        # Base Asset: if recent 'high' finding => Current Threat
        elif has_recent_findings(base_asset, 'high', settings.PAL_MAX_DAYS):
            resp_ok = slack_alert(base_asset, 'New', '{} current threats'.format(ASSETGROUP_BASE_NAME), test_only=test_only)
            if not resp_ok:
                continue
            LOGGER.warning(
                'move asset %s from %s to %s',
                base_asset,
                ASSETGROUP_BASE_NAME,
                '{} current threats'.format(ASSETGROUP_BASE_NAME))
            move_asset(
                base_asset,
                settings.PAL_GROUP_ID,
                ASSETGROUP_BASE_NAME,
                current_threats_group_id,
                '{} current threats'.format(ASSETGROUP_BASE_NAME),
                test_only=test_only)
            if current_threats_group_id is None:
                current_threats_group_id, _ = get_group_ids()
        # Base Asset: if only old 'high' findings => Archived Threat
        elif has_old_findings(base_asset, 'high', settings.PAL_MAX_DAYS):
            resp_ok = slack_alert(base_asset, 'New', '{} archived threats'.format(ASSETGROUP_BASE_NAME), criticity='low', test_only=test_only)
            if not resp_ok:
                continue
            LOGGER.warning(
                'move asset %s from %s to %s',
                base_asset,
                ASSETGROUP_BASE_NAME,
                '{} archived threats'.format(ASSETGROUP_BASE_NAME))
            move_asset(
                base_asset,
                settings.PAL_GROUP_ID,
                ASSETGROUP_BASE_NAME,
                archived_threats_group_id,
                '{} archived threats'.format(ASSETGROUP_BASE_NAME),
                test_only=test_only)
            if archived_threats_group_id is None:
                _, archived_threats_group_id = get_group_ids()


def archived_asset_lifecycle(at_assets, archived_threats_group_id, current_threats_group_id, test_only=False):
    """
    Archived asset handler
    """
    if not at_assets:
        return
    for archived_asset in at_assets:
        has_recent_high_finding = has_recent_findings(archived_asset, 'high', settings.PAL_MAX_DAYS)
        has_current_ip = current_ip_exists(archived_asset)
        is_for_sale = domain_for_sale(archived_asset)
        # Archive Asset: Ignore no recent findings or without IP or domain for sale
        if not has_recent_high_finding or not has_current_ip or is_for_sale:
            continue
        # Archive Asset: in any other case, this is a current threat
        resp_ok = slack_alert(archived_asset, 'Archived', '{} current threats'.format(ASSETGROUP_BASE_NAME), test_only=test_only)
        if not resp_ok:
            continue
        LOGGER.warning(
            'move asset %s from %s to %s',
            archived_asset,
            '{} archived threats'.format(ASSETGROUP_BASE_NAME),
            '{} current threats'.format(ASSETGROUP_BASE_NAME))
        move_asset(
            archived_asset,
            archived_threats_group_id,
            '{} archived threats'.format(ASSETGROUP_BASE_NAME),
            current_threats_group_id,
            '{} current threats'.format(ASSETGROUP_BASE_NAME),
            test_only=test_only)
        if current_threats_group_id is None:
            current_threats_group_id, _ = get_group_ids()

def threat_asset_lifecycle(ct_assets, archived_threats_group_id, current_threats_group_id, test_only=False):
    """
    Threat asset handler
    """
    if not ct_assets:
        return
    for threat_asset in ct_assets:
        has_recent_high_finding = has_recent_findings(threat_asset, 'high', settings.PAL_MAX_DAYS)
        has_current_ip = current_ip_exists(threat_asset)
        is_for_sale = domain_for_sale(threat_asset)
        # Threat Asset: Ignore recent findings, with IP and not for sale
        if has_recent_high_finding and has_current_ip and not is_for_sale:
            continue
        # Threat Asset: in any other case, this is an archived threat
        resp_ok = slack_alert(threat_asset, 'Current', '{} archived threats'.format(ASSETGROUP_BASE_NAME), criticity='low', test_only=test_only)
        if not resp_ok:
            continue
        LOGGER.warning(
            'move asset %s from %s to %s',
            threat_asset,
            '{} current threats'.format(ASSETGROUP_BASE_NAME),
            '{} archived threats'.format(ASSETGROUP_BASE_NAME))
        move_asset(
            threat_asset,
            current_threats_group_id,
            '{} current threats'.format(ASSETGROUP_BASE_NAME),
            archived_threats_group_id,
            '{} archived threats'.format(ASSETGROUP_BASE_NAME),
            test_only=test_only)
        if archived_threats_group_id is None:
            _, archived_threats_group_id = get_group_ids()


def main(test_only=False):
    """
    Main function
    """
    current_threats_group_id, archived_threats_group_id = get_group_ids()

    base_assets = get_assets(settings.PAL_GROUP_ID)
    ct_assets = list()
    if current_threats_group_id is not None:
        ct_assets = get_assets(current_threats_group_id)
    at_assets = list()
    if archived_threats_group_id is not None:
        at_assets = get_assets(archived_threats_group_id)

    if not base_assets and not ct_assets and not at_assets:
        LOGGER.warning('no assets')
    else:
        base_asset_lifecycle(
            base_assets,
            archived_threats_group_id,
            current_threats_group_id,
            test_only=test_only)
        archived_asset_lifecycle(
            at_assets,
            archived_threats_group_id,
            current_threats_group_id,
            test_only=test_only)
        threat_asset_lifecycle(
            ct_assets,
            archived_threats_group_id,
            current_threats_group_id,
            test_only=test_only)


if __name__ == '__main__':
    DEBUG = len(sys.argv) > 1 and sys.argv[1] == '--test-only'
    main(test_only=DEBUG)
