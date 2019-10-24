#!/usr/bin/env python
#-*- coding: utf-8 -*-
""" Patrowl Slack Reporter """

# Standard library imports
import base64
from datetime import datetime, timezone
import json
import logging
import time

# Third party library imports
from dateutil.parser import parse
from patrowl4py.api import PatrowlManagerApi
from requests import Session

# Own libraries
import settings

# Debug
# from pdb import set_trace as st

PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

VERSION = '1.1.0'

VIRUSTOTAL_WHOIS_FIELDS = [
    'Creation Date',
    'Name Server',
    'Nserver',
    'Registrant Country',
    'Registrar Abuse Contact Email',
    'Registrar URL',
    'Registrar',
]

LOGGER = logging.getLogger('patrowl-slack-reporter')

SESSION = Session()

def get_recent_assets():
    ''' Returns the last created assets '''
    assets_list = []
    assets = list()
    for group_id in settings.LIST_GROUP_ID:
        assetgroup = PATROWL_API.get_assetgroup_by_id(group_id)
        assets += sorted(assetgroup['assets'], key=lambda k: k['id'], reverse=True)

    for asset in assets:
        created_at = PATROWL_API.get_asset_by_id(asset['id'])['created_at']
        now = datetime.now(timezone.utc).astimezone()
        now.isoformat()
        now = str(now).replace(' ', 'T')
        now = parse(now)
        created_at = parse(created_at)
        diff = (now - created_at).total_seconds()
        if diff <= settings.FREQUENCY_SECOND:
            assets_list.append(asset)
            asset = PATROWL_API.get_asset_by_id(asset['id'])
    return assets_list


def start_scan(name, assets, engine_policy):
    """
    run scan
    """
    scan = PATROWL_API.get_scans(title='{} report'.format(name))

    # Delete old scans which aren't started or enqueued
    for scan in PATROWL_API.get_scan_definitions():
        if scan['title'] == '{} report'.format(name):
            if scan['status'] in ['enqueued', 'started']:
                return scan['status'], None
            PATROWL_API.delete_scan_definition(scan['id'])

    retry = False
    try:
        PATROWL_API.add_scan_definition(
            engine_policy=engine_policy,
            title='{} report'.format(name),
            description='{} report'.format(name),
            scan_type='single',
            start_scan='now',
            assets=[asset['id'] for asset in assets])
    except:
        retry = True

    # Need to warm up Patrowl sometimes...
    if retry:
        scan = PATROWL_API.get_scans(title='{} report'.format(name))
        if scan:
            for scan_to_delete in scan:
                PATROWL_API.delete_scan_definition(scan_to_delete['scan_definition'])
        try:
            PATROWL_API.add_scan_definition(
                engine_policy=engine_policy,
                title='{} report'.format(name),
                description='{} report'.format(name),
                scan_type='single',
                start_scan='now',
                assets=[asset['id'] for asset in assets])
        except:
            return 'error', None

    new_scan = PATROWL_API.get_scans(title='{} report'.format(name))
    if new_scan:
        return new_scan[0]['status'], new_scan[0]['id']
    return 'error', None


def get_current_status(scan_id):
    """
    Returns the current status of the scan specified
    """
    try:
        res = PATROWL_API.get_scan_by_id(scan_id)
    except:
        return 'error'
    if 'detail' in res and res['detail'] == 'Not found.':
        return 'error'
    if 'status' in res and res['status'] in ['error', 'finished']:
        return res['status']
    return 'running'


def get_eyewitness_report(scan_id, report):
    """
    This function returns the Eyewitness report
    """
    try:
        res = PATROWL_API.get_scan_by_id(scan_id)
    except:
        return report
    if 'detail' in res and res['detail'] == 'Not found.':
        return report
    for asset in res['assets']:
        asset_id = asset['id']
        if asset_id not in report:
            report[asset_id] = dict()
        for finding in PATROWL_API.get_asset_findings_by_id(asset_id):
            # Get the last screenshot
            if finding['scan'] == scan_id:
                if 'links' in finding:
                    report[asset_id]['links'] = finding['links']

    return report


def get_virustotal_report(scan_id, report):
    """
    This function returns the VirusTotal report
    """
    try:
        res = PATROWL_API.get_scan_by_id(scan_id)
    except:
        return report
    if 'detail' in res and res['detail'] == 'Not found.':
        return report
    for asset in res['assets']:
        asset_id = asset['id']
        if asset_id not in report:
            report[asset_id] = dict()
        for finding in PATROWL_API.get_asset_findings_by_id(asset_id):
            if finding['type'] == 'domain_whois' and 'whois' not in report:
                # Gen whois description
                report[asset_id]['whois'] = dict()
                for data in finding['description'].split('\n'):
                    if ': ' not in data:
                        continue
                    key = data.split(': ')[0]
                    value = data.split(': ')[1]
                    if key != '' and value != '':
                        report[asset_id]['whois'][key.lower()] = value
            if finding['type'] == 'subdomain_list' and 'subdomain_list' not in report:
                report[asset_id]['subdomain_list'] = finding['raw_data']['subdomain_list']
    return report


def scan():
    """
    This is the main function
    """
    LOGGER.warning('Start scan')
    recent_assets = get_recent_assets()

    if not recent_assets:
        LOGGER.warning('no assets')
        return dict()

    eye_scan, eye_scan_id = start_scan('Eyewitness', assets=recent_assets, engine_policy=settings.EYEWITNESS_POLICY)
    vt_scan, vt_scan_id = start_scan('Virustotal', assets=recent_assets, engine_policy=settings.VIRUSTOTAL_POLICY)

    nb_try = 39 # 13mn
    status = {
        'global': 'running',
        settings.EYEWITNESS_POLICY: 'running',
        settings.VIRUSTOTAL_POLICY: 'running'
    }
    while nb_try > 0 and status['global'] == 'running':

        # Eyewitness
        if status[settings.EYEWITNESS_POLICY] == 'running':
            if eye_scan in ['error', 'finished']:
                status[settings.EYEWITNESS_POLICY] = eye_scan
            else:
                status[settings.EYEWITNESS_POLICY] = get_current_status(eye_scan_id)
                # Retry
                if status[settings.EYEWITNESS_POLICY] == 'error':
                    status[settings.EYEWITNESS_POLICY] = get_current_status(eye_scan_id)
        # Virustotal
        if status[settings.VIRUSTOTAL_POLICY] == 'running':
            if vt_scan in ['error', 'finished']:
                status[settings.VIRUSTOTAL_POLICY] = vt_scan
            else:
                status[settings.VIRUSTOTAL_POLICY] = get_current_status(vt_scan_id)
                # Retry
                if status[settings.VIRUSTOTAL_POLICY] == 'error':
                    status[settings.VIRUSTOTAL_POLICY] = get_current_status(vt_scan_id)

        # Update global status
        if status[settings.EYEWITNESS_POLICY] != 'running' and \
           status[settings.VIRUSTOTAL_POLICY] != 'running':
            status['global'] = 'finished'
        else:
            LOGGER.warning('global status: %s', status)
            time.sleep(20)
            nb_try -= 1

    report = dict()

    # Gen report
    for asset in recent_assets:
        report[asset['id']] = dict()
        report[asset['id']]['name'] = asset['name']

    # Eyewitness
    if status[settings.EYEWITNESS_POLICY] == 'finished':
        report = get_eyewitness_report(eye_scan_id, report)

    # Virustotal
    if status[settings.VIRUSTOTAL_POLICY] == 'finished':
        report = get_virustotal_report(vt_scan_id, report)

    LOGGER.warning('Report Done')

    return report


def download_picture(url):
    """
    This function upload the screenshot from Eyewitness
    """
    if settings.EYEWITNESS_BASICAUTH:
        data = base64.b64encode('{}:{}'.format(settings.EYEWITNESS_USERNAME, settings.EYEWITNESS_PASSWORD).encode('utf-8')).decode()
        req = SESSION.get(url, headers={'Authorization': 'Basic {}'.format(data)})
    else:
        req = SESSION.get(url)

    open('picture.png', 'wb').write(req.content)


def upload_picture_on_slack(title):
    """
    This function upload a picture on Slack
    """
    my_file = {'file' : ('picture.png', open('picture.png', 'rb'), 'png')}
    payload = {
        'filename': '{}.png'.format(title),
        'token': settings.SLACK_LEGACY_TOKEN,
        'channels': settings.SLACK_CHANNEL
    }
    SESSION.post('https://slack.com/api/files.upload', params=payload, files=my_file)


def slack_alert(report):
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
        attachments['pretext'] = settings.SLACK_PRETEXT
        attachments['text'] = 'hxxps://{}/'.format(data['name'].replace('.', '[.]'))
        attachments['fields'] = []

        for whois_field in VIRUSTOTAL_WHOIS_FIELDS:
            if 'whois' in data and whois_field.lower() in data['whois']:
                attachments['fields'].append({'title': whois_field, 'value': data['whois'][whois_field.lower()], 'short': False})

        payload['attachments'] = [attachments]

        SESSION.post(settings.SLACK_WEBHOOK, data=json.dumps(payload))

        if 'links' in data and data['links']:
            download_picture(data['links'][0])
            upload_picture_on_slack(data['name'])

if __name__ == '__main__':
    REPORT = scan()
    slack_alert(REPORT)
