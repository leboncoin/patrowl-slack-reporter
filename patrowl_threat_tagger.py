#!/usr/bin/env python
#-*- coding: utf-8 -*-
""" Patrowl Threat Tagger """

# Standard library imports
import json
import logging
import os
import random
import re

# Third party library imports
from datetime import datetime
from dateutil.parser import parse
from dns.resolver import query
# from patrowl4py.api import PatrowlManagerApi
from Patrowl4py.patrowl4py.api import PatrowlManagerApi
from requests import Session
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Own libraries
import patrowl_threat_tagger_settings as settings

# Debug
from pdb import set_trace as st

VERSION = '1.1.0'

PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)

LOGGER = logging.getLogger('patrowl-threat-tagger')

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


def fqdn_ips(fqdn):
    """
    Returns the list of IPs for a fqdn
    """
    resolved_ips = list()
    try:
        for ip_address in query(fqdn):
            resolved_ips.append(str(ip_address))
    except:
        return resolved_ips

    resolved_ips.sort()

    return resolved_ips


def add_finding(asset, title, criticity):
    try:
        PATROWL_API.add_finding(
            title,
            title,
            'patrowl_threat_tagger',
            criticity,
            asset['id'])
    except:
        pass


def delete_finding(finding_id):
    try:
        PATROWL_API.delete_finding(
            finding_id)
    except:
        pass


def generate_random_codename(seed):
    random.seed(seed)
    with open('adjectives.txt', 'r') as adjectives_file:
        adjectives = adjectives_file.read()
    adjective = random.choice(adjectives.split('\n'))
    with open('animals.txt', 'r') as animals_file:
        animals = animals_file.read()
    animal = random.choice(animals.split('\n'))
    return '{} {}'.format(adjective, animal)


def update_ip_finding(asset, ct_findings):
    """
    This function update 'Current IP: xx.xx.xx.xx'
    """
    asset_findings = ct_findings[asset['id']]
    list_ip = fqdn_ips(asset['name'])
    if list_ip:
        current_ip = list_ip[0]
    else:
        current_ip = 'No IP'
    add_current_ip_finding = True
    threat_codename = None
    for i, finding in enumerate(asset_findings):
        # Update 'Current IP' finding
        if 'Current IP: ' in finding['title'] \
            and finding['title'] != 'Current IP: {}'.format(current_ip):
            LOGGER.warning('Remove "Current IP" finding for %s', asset['name'])
            delete_finding(finding['id'])
            ct_findings[asset['id']][i]['title'] = 'Current IP: {}'.format(current_ip)
        elif finding['title'] == 'Current IP: {}'.format(current_ip):
            add_current_ip_finding = False
        elif 'Threat codename: ' in finding['title']:
            threat_codename = finding

    if add_current_ip_finding:
        LOGGER.warning('Add "Current IP: %s" for %s', current_ip, asset['name'])
        add_finding(asset, 'Current IP: {}'.format(current_ip), 'info')
        ct_findings[asset['id']].append({'title': 'Current IP: {}'.format(current_ip)})

    # Check if "Threat codename" needs an update
    if threat_codename is not None and current_ip != 'No IP':
        old_ip = current_ip
        match = re.search(re.compile('\((.*)\)'), threat_codename['title'])
        # Should always matches
        if match:
            old_ip = match.group(1)
        if old_ip != current_ip:
            # Rename "Threat codename" finding IP
            LOGGER.warning('Rename "%s" for %s', threat_codename['title'], asset['name'])
            for i, finding in enumerate(ct_findings[asset['id']]):
                if 'Threat codename' in finding['title']:
                    ct_findings[asset['id']][i] = {
                        'severity': threat_codename['severity'],
                        'title': threat_codename['title'],
                        'updated_at': threat_codename['updated_at'],
                        'asset': asset['id']}
            delete_finding(threat_codename['id'])
            add_finding(
                asset,
                threat_codename['title'].replace(old_ip, current_ip),
                threat_codename['severity'])
            ct_findings[asset['id']].append({'title': 'Current IP: {}'.format(current_ip)})

    return ct_findings


def update_current_threat(asset, ct_findings):
    """
    This function update 'Threat codename: xxxx (xx.xx.xx.xx)'
    """
    asset_findings = ct_findings[asset['id']]
    threat_codename = dict()
    threat_codename['present'] = False
    threat_codename['finding'] = None
    threat_codename['new_finding'] = None
    current_ip = 'No IP'
    for finding in asset_findings:
        # Search 'Threat codename' finding
        if 'Threat codename: ' in finding['title']:
            threat_codename['present'] = True
            threat_codename['finding'] = finding
        # Search 'Current IP' finding
        if 'Current IP: ' in finding['title']:
            match = re.search(re.compile('Current IP: (.*)'), finding['title'])
            if match:
                current_ip = match.group(1)

    # Get latest current threat 'Threat codename' finding
    for ct_asset_id in ct_findings:
        for finding in ct_findings[ct_asset_id]:
            if 'Threat codename: ' in finding['title'] \
                and '({})'.format(current_ip) in finding['title']:
                if threat_codename['new_finding'] is None:
                    threat_codename['new_finding'] = finding
                else:
                    updated_at = parse(finding['updated_at'])
                    updated_at_new = parse(threat_codename['new_finding']['updated_at'])
                    if updated_at > updated_at_new:
                        threat_codename['new_finding'] = finding

    # New threat
    if not threat_codename['present'] \
        and threat_codename['new_finding'] is None \
        and current_ip != 'No IP':
        codename = generate_random_codename(current_ip)
        LOGGER.warning('New threat : "Threat codename: %s (%s)" for %s', codename, current_ip, asset['name'])
        slack_alert('New threat', 'Threat codename: {} ({})'.format(codename, current_ip), asset)
        ct_findings[asset['id']].append({
            'severity': 'high',
            'title': 'Threat codename: {} ({})'.format(codename, current_ip),
            'updated_at': datetime.now().isoformat(),
            'asset': asset['id']})
        add_finding(asset, 'Threat codename: {} ({})'.format(codename, current_ip), 'high')

    # New asset in existing threat
    elif not threat_codename['present'] \
        and threat_codename['new_finding'] is not None \
        and current_ip != 'No IP':
        LOGGER.warning('New asset in existing threat : "%s" for %s', threat_codename['new_finding']['title'], asset['name'])
        slack_alert('New asset in existing threat', threat_codename['new_finding']['title'], asset)
        ct_findings[asset['id']].append({
            'severity': threat_codename['new_finding']['severity'],
            'title': threat_codename['new_finding']['title'],
            'updated_at': threat_codename['new_finding']['updated_at'],
            'asset': asset['id']})
        add_finding(asset, threat_codename['new_finding']['title'], threat_codename['new_finding']['severity'])

    # Rename current threat, only if different
    elif threat_codename['present'] \
        and threat_codename['new_finding'] is not None \
        and current_ip != 'No IP' \
        and threat_codename['new_finding']['asset'] != asset['id'] \
        and (threat_codename['new_finding']['title'] != threat_codename['finding']['title']\
            or threat_codename['new_finding']['severity'] != threat_codename['finding']['severity']):
        LOGGER.warning('Rename current threat : "%s" for %s', threat_codename['new_finding']['title'], asset['name'])
        slack_alert('Rename current threat', threat_codename['new_finding']['title'], asset, criticity='info')
        for i, finding in enumerate(ct_findings[asset['id']]):
            if 'Threat codename' in finding['title']:
                ct_findings[asset['id']][i] = {
                    'severity': threat_codename['new_finding']['severity'],
                    'title': threat_codename['new_finding']['title'],
                    'updated_at': threat_codename['new_finding']['updated_at'],
                    'asset': asset['id']}
        delete_finding(threat_codename['finding']['id'])
        add_finding(asset, threat_codename['new_finding']['title'], threat_codename['new_finding']['severity'])

    return ct_findings

def update_threat(asset, asset_findings, ct_findings):
    """
    This function updates the threat of Base and Archived assets
    """
    threat_codename = dict()
    threat_codename['present'] = False
    threat_codename['finding'] = None
    threat_codename['new_finding'] = None
    current_ip = 'No IP'
    for finding in asset_findings:
        # Search 'Threat codename' finding
        if 'Threat codename: ' in finding['title']:
            threat_codename['present'] = True
            threat_codename['finding'] = finding
        # Search 'Current IP' finding
        if 'Current IP: ' in finding['title']:
            match = re.search(re.compile('Current IP: (.*)'), finding['title'])
            if match:
                current_ip = match.group(1)

    # Get latest current threat 'Threat codename' finding
    for ct_asset_id in ct_findings:
        for finding in ct_findings[ct_asset_id]:
            if 'Threat codename: ' in finding['title'] \
                and '({})'.format(current_ip) in finding['title']:
                if threat_codename['new_finding'] is None:
                    threat_codename['new_finding'] = finding
                else:
                    updated_at = parse(finding['updated_at'])
                    updated_at_new = parse(threat_codename['new_finding']['updated_at'])
                    if updated_at > updated_at_new:
                        threat_codename['new_finding'] = finding

    # New asset in existing threat
    if not threat_codename['present'] \
        and threat_codename['new_finding'] is not None \
        and current_ip != 'No IP':
        LOGGER.warning('New asset in existing threat : "%s" for %s', threat_codename['new_finding']['title'], asset['name'])
        slack_alert('New asset in existing threat', threat_codename['new_finding']['title'], asset)
        add_finding(asset, threat_codename['new_finding']['title'], threat_codename['new_finding']['severity'])

    # Rename current threat, only if different
    elif threat_codename['present'] \
        and threat_codename['new_finding'] is not None \
        and current_ip != 'No IP' \
        and threat_codename['new_finding']['asset'] != asset['id'] \
        and (threat_codename['new_finding']['title'] != threat_codename['finding']['title'] \
            or threat_codename['new_finding']['severity'] != threat_codename['finding']['severity']):
        LOGGER.warning('Rename current threat : "%s" for %s', threat_codename['new_finding']['title'], asset['name'])
        slack_alert('Rename current threat', threat_codename['new_finding']['title'], asset, criticity='info')
        delete_finding(threat_codename['finding']['id'])
        add_finding(asset, threat_codename['new_finding']['title'], threat_codename['new_finding']['severity'])


def slack_alert(threat_type, threat_title, asset, criticity='high'):
    """
    Post report on Slack
    """
    payload = dict()
    payload['channel'] = settings.SLACK_CHANNEL
    payload['link_names'] = 1
    payload['username'] = settings.SLACK_USERNAME
    payload['icon_emoji'] = settings.SLACK_ICON_EMOJI

    attachments = dict()
    attachments['pretext'] = '{} - {}'.format(threat_type, threat_title)
    attachments['fields'] = []
    attachments['color'] = COLOR_MAPPING[criticity]

    attachments['text'] = safe_url(asset['name'])
    attachments['fields'].append({'title': 'Patrowl asset link', 'value': '{}/assets/details/{}'.format(settings.PATROWL_PUBLIC_ENDPOINT, asset['id'])})

    payload['attachments'] = [attachments]

    response = SESSION.post(settings.SLACK_WEBHOOK, data=json.dumps(payload))

    return response.ok


def main():
    """
    Main function
    """
    if not os.path.exists('adjectives.txt') and not not os.path.exists('animals.txt'):
        LOGGER.critical('You need both adjectives.txt and animals.txt')
        exit(1)

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
        ct_findings = get_findings(ct_assets)
        for ct_asset in ct_assets:
            ct_findings = update_ip_finding(ct_asset, ct_findings)
        for ct_asset in ct_assets:
            ct_findings = update_current_threat(ct_asset, ct_findings)

        base_findings = get_findings(base_assets)
        for base_asset in base_assets:
            update_ip_finding(base_asset, base_findings)
            update_threat(base_asset, base_findings[base_asset['id']], ct_findings)
        at_findings = get_findings(at_assets)
        for at_asset in at_assets:
            update_ip_finding(at_asset, at_findings)
            update_threat(at_asset, at_findings[at_asset['id']], ct_findings)


if __name__ == '__main__':
    main()
