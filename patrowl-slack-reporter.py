#!/usr/bin/env python
#-*- coding: utf-8 -*-
""" Patrowl Slack Reporter """

# Standard library imports
import json
import logging

# Third party library imports
# from patrowl4py.api import PatrowlManagerApi
from requests import Session
from libs.Patrowl4py.patrowl4py.api import PatrowlManagerApi

# Own libraries
import settings

# Debug
# from pdb import set_trace as st

VERSION = '2.0.0'

WARNINGS_TYPE_BLACKLIST = [
    'certstream_report',
]

COLOR_MAPPING = {
    'info': '#b4c2bf',
    'low': '#4287f5',
    'medium': '#f5a742',
    'high': '#b32b2b',
}

PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

LOGGER = logging.getLogger('patrowl-slack-reporter')

SESSION = Session()

def safe_url(text):
    """
    Returns a safe unclickable link
    """
    return text.replace('http:', 'hxxp:').replace('https:', 'hxxps:').replace('.', '[.]')

def get_assets_from_groups():
    """
    Returns the assets Ids from all specified groups
    """
    assets = list()
    for group_id in settings.LIST_GROUP_ID:
        assetgroup = PATROWL_API.get_assetgroup_by_id(group_id)
        assets += sorted(assetgroup['assets'], key=lambda k: k['id'], reverse=True)
    return assets

def get_new_assets(assets):
    """
    Returns the report of new assets
    """
    report = dict()
    for asset in assets:
        asset_data = PATROWL_API.get_asset_by_id(asset['id'])
        if asset_data['status'] == 'new':
            report[asset['id']] = asset_data

    LOGGER.warning('Found %s new assets.', len(report))

    return report

def get_new_findings(assets, severities):
    """
    Returns the report of new findings
    """
    report = dict()
    for asset in assets:
        for finding in PATROWL_API.get_asset_findings_by_id(asset['id']):
            if finding['status'] == 'new' \
                and finding['severity'] in severities \
                and finding['type'] not in WARNINGS_TYPE_BLACKLIST:
                report[finding['id']] = finding

    LOGGER.warning('Found %s new findings.', len(report))

    return report

def slack_alert(report, object_type):
    """
    Post report on Slack
    """
    for (_, data) in report.items():
        payload = dict()
        payload['channel'] = settings.SLACK_CHANNEL
        payload['link_names'] = 1
        payload['username'] = settings.SLACK_USERNAME
        payload['icon_emoji'] = settings.SLACK_ICON_EMOJI

        attachments = dict()
        attachments['pretext'] = 'New {} identified'.format(object_type)
        attachments['fields'] = []
        attachments['color'] = COLOR_MAPPING['info']

        if object_type == 'asset':
            attachments['text'] = safe_url(data['name'])
            attachments['fields'].append({'title': 'Created At', 'value': data['created_at']})
            attachments['fields'].append({'title': 'Patrowl asset link', 'value': '{}/assets/details/{}'.format(settings.PATROWL_PUBLIC_ENDPOINT, data['id'])})
        elif object_type == 'finding':
            attachments['text'] = safe_url(data['title'])
            attachments['fields'].append({'title': 'Asset Name', 'value': safe_url(data['asset_name'])})
            attachments['fields'].append({'title': 'Severity', 'value': data['severity']})
            if data['links']:
                attachments['fields'].append({'title': 'Links', 'value': ' '.join(data['links'])})
            if data['severity'] in COLOR_MAPPING:
                attachments['color'] = COLOR_MAPPING[data['severity']]
            attachments['fields'].append({'title': 'Patrowl finding link', 'value': '{}/findings/details/{}'.format(settings.PATROWL_PUBLIC_ENDPOINT, data['id'])})
            attachments['fields'].append({'title': 'Patrowl asset link', 'value': '{}/assets/details/{}'.format(settings.PATROWL_PUBLIC_ENDPOINT, data['asset'])})

        payload['attachments'] = [attachments]

        response = SESSION.post(settings.SLACK_WEBHOOK, data=json.dumps(payload))

        if response.ok and object_type == 'asset':
            PATROWL_API.ack_asset_by_id(data['id'])
        elif response.ok and object_type == 'finding':
            PATROWL_API.ack_finding(data['id'])

if __name__ == '__main__':
    ASSETS = get_assets_from_groups()
    slack_alert(get_new_assets(ASSETS), 'asset')
    slack_alert(get_new_findings(ASSETS, ['low', 'medium', 'high']), 'finding')
