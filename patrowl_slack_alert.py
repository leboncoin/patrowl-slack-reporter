#!/usr/bin/env python
"""
Patrowl Slack Alert

Copyright 2020 Leboncoin
Licensed under the Apache License
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)
"""

# Standard library imports
import json
import logging
import re

# Third party library imports
from patrowl4py.api import PatrowlManagerApi
from requests import Session
import urllib3

# Own libraries
import settings

# Debug
# from pdb import set_trace as st

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = '2.6.0'

WARNINGS_TYPE_BLACKLIST = [
    'certstream_report',
    'patrowl_threat_tagger',
]

COLOR_MAPPING = {
    'info': '#b4c2bf',
    'low': '#4287f5',
    'medium': '#f5a742',
    'high': '#b32b2b',
    'critical': '#b32b2b',
}

PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

logging.basicConfig()
LOGGER = logging.getLogger('patrowl-slack-alert')

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
    for group_id in settings.PSA_LIST_GROUP_ID:
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
        if 'status' in asset_data and asset_data['status'] == 'new':
            report[asset['id']] = asset_data

    LOGGER.warning('Found %s new assets.', len(report))

    return report

def get_new_findings(assets, severities):
    """
    Returns the report of new findings
    """
    report = dict()
    assets_update_list = list()
    for asset in assets:
        asset['is_for_sale'] = False
        asset['current_ip'] = 'No IP'
        asset['first_screenshot'] = None
        asset['has_multiple_screenshots'] = False
        for finding in PATROWL_API.get_asset_findings_by_id(asset['id']):
            if 'Domain for sale: ' in finding:
                asset['is_for_sale'] = finding['title'].replace('Domain for sale: ', '') == 'True'
            if 'Current IP: ' in finding['title']:
                asset['current_ip'] = finding['title'].split('Current IP: ', 1)[1]

            if 'status' in finding and finding['status'] == 'new' \
                and finding['severity'] in severities \
                and finding['type'] not in WARNINGS_TYPE_BLACKLIST:
                report[finding['id']] = finding
                assets_update_list.append(asset)
            # Looking for the first screenshot
            elif finding['type'] in ['eyewitness_screenshot']:
                if 'status' in finding and finding['status'] != 'new':
                    asset['has_multiple_screenshots'] = True
                if not asset['has_multiple_screenshots'] and asset['first_screenshot'] is None:
                    asset['first_screenshot'] = finding
                elif not asset['has_multiple_screenshots'] and asset['first_screenshot'] is not None:
                    asset['has_multiple_screenshots'] = True

        # This is the case when there is only one screenshot
        if not asset['has_multiple_screenshots'] and asset['first_screenshot'] is not None:
            report[asset['first_screenshot']['id']] = asset['first_screenshot']
            assets_update_list.append(asset)

    for (_, data) in report.items():
        for asset in assets_update_list:
            if asset['name'] == data['asset_name']:
                report[data['id']]['is_for_sale'] = asset['is_for_sale']
                report[data['id']]['current_ip'] = asset['current_ip']

    LOGGER.warning('Found %s new findings.', len(report))
    return report

def gen_eyewitness_diff(links):
    """
    Return an eyewitness diff link
    """
    diff_page = '/eyewitness_diff.html'
    oldscan = 0
    newscan = 0
    assetid = 0
    ishttps = 0
    imgfilename = ''
    for link in links:
        fqdn = link.split('/')[2]
        if oldscan == 0 and newscan == 0:
            newscan = oldscan = link.split('/')[3]
        elif newscan > link.split('/')[3]:
            oldscan = link.split('/')[3]
        else:
            newscan = link.split('/')[3]
        assetid = link.split('/')[4]
        ishttps = link.split('/')[5]
        imgfilename = link.split('/')[7]
    return 'https://{}{}?oldscan={}&newscan={}&assetid={}&ishttps={}&imgfilename={}'.format(
        fqdn, diff_page, oldscan, newscan, assetid, ishttps, imgfilename)

def slack_alert(report, object_type):
    """
    Post report on Slack
    """
    for (_, data) in report.items():
        payload = dict()
        payload['channel'] = settings.SLACK_CHANNEL
        payload['link_names'] = 1
        payload['username'] = settings.PSA_SLACK_USERNAME
        payload['icon_emoji'] = settings.PSA_SLACK_ICON_EMOJI

        attachments = dict()
        severity = 'info'
        if 'severity' in data:
            severity = data['severity']

        attachments['color'] = COLOR_MAPPING[severity]

        attachments['blocks'] = list()

        # First section: Title
        if object_type == 'asset':
            attachments['blocks'].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*New asset identified*\n{}".format(safe_url(data['name']))
                    }
                })
        elif object_type == 'finding':
            attachments['blocks'].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*New finding identified*\n{}".format(safe_url(data['title']))
                    }
                })

        # Second section: Description
        if object_type == 'asset':
            attachments['blocks'].append({
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Created At:*\n{}".format(data['created_at'])
                    }
                    ]
                })
        elif object_type == 'finding':
            fields = [
                {
                    "type": "mrkdwn",
                    "text": "*Asset Name:*\n{}".format(safe_url(data['asset_name']))
                },
                {
                    "type": "mrkdwn",
                    "text": "*Severity:*\n{}".format(data['severity'])
                }
            ]
            if 'links' in data and data['links']:
                if data['type'] != 'eyewitness_screenshot_diff':
                    for i, link in enumerate(data['links']):
                        fields.append({
                            "type": "mrkdwn",
                            "text": "*Additionnal link:*\n<{}|{}>".format(link, 'Link #'+str(i))
                        })
            if data['type'] == 'aws_tower':
                dns_record = re.findall('"DnsRecord": "([a-zA-Z0-9\.\-_]+)"', data['description'])
                if dns_record:
                    fields.append({
                        "type": "mrkdwn",
                        "text": f"*Dns Record:*\n<https://{dns_record[0]}|{dns_record[0]}>"
                    })

            attachments['blocks'].append({
                "type": "section",
                "fields": fields
                })

        # Third section: Divider
        attachments['blocks'].append({
            "type": "divider"
        })

        # Fourth section: Button
        if object_type == 'asset':
            attachments['blocks'].append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "emoji": True,
                            "text": "Patrowl Asset"
                        },
                        "style": "primary",
                        "url": '{}/assets/details/{}'.format(settings.PATROWL_PUBLIC_ENDPOINT, data['id'])
                    }
                ]
            })
        elif object_type == 'finding':
            elements = list()
            if data['type'] == 'eyewitness_screenshot_diff':
                elements.append({
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "emoji": True,
                        "text": "Show screenshot diff"
                    },
                    "style": "primary",
                    "url": gen_eyewitness_diff(data['links'])
                })
            elements.append(
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "emoji": True,
                        "text": "Patrowl finding"
                    },
                    "url": '{}/findings/details/{}'.format(settings.PATROWL_PUBLIC_ENDPOINT, data['id'])
                })
            elements.append(
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "emoji": True,
                        "text": "Patrowl asset"
                    },
                    "url": '{}/assets/details/{}'.format(settings.PATROWL_PUBLIC_ENDPOINT, data['asset'])
                })
            attachments['blocks'].append({
                "type": "actions",
                "elements": elements
            })


        payload['attachments'] = [attachments]
        response = SESSION.post(settings.SLACK_WEBHOOK, data=json.dumps(payload))

        if response.ok and object_type == 'asset':
            PATROWL_API.ack_asset_by_id(data['id'])
        elif response.ok and object_type == 'finding':
            PATROWL_API.ack_finding(data['id'])

if __name__ == '__main__':
    ASSETS = get_assets_from_groups()
    slack_alert(get_new_assets(ASSETS), 'asset')
    slack_alert(get_new_findings(ASSETS, ['medium', 'high', 'critical']), 'finding')
