#!/usr/bin/env python
"""
Patrowl Asset Tagger

Copyright (c) 2020 Nicolas Beguier
Licensed under the Apache License
Written by Nicolas BEGUIER (nicolas_beguier@hotmail.com)
"""


# Standard library imports
from datetime import datetime
import json
import logging
import os
import random
import re
import sys

# Third party library imports
from dns.resolver import NoAnswer, NoNameservers, NXDOMAIN, Resolver
from dns.exception import DNSException
from patrowl4py.api import PatrowlManagerApi
from requests import Session
import urllib3

# Own libraries
import settings

# Debug
# from pdb import set_trace as st

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = '1.7.0'

logging.basicConfig()
LOGGER = logging.getLogger('patrowl-asset-tagger')
PATROWL_API = PatrowlManagerApi(
    url=settings.PATROWL_PRIVATE_ENDPOINT,
    auth_token=settings.PATROWL_APITOKEN
)
SESSION = Session()

ASSETGROUP_BASE_NAME = PATROWL_API.get_assetgroup_by_id(settings.PAT_GROUP_ID)['name']
COLOR_MAPPING = {
    'info': '#b4c2bf',
    'low': '#4287f5',
    'medium': '#f5a742',
    'high': '#b32b2b',
}

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
            if 'title' in finding and ( \
                'Current IP: ' in finding['title'] \
                or 'Threat codename: ' in finding['title'] \
                or 'Some domain has been screenshoted by eyewitness' in finding['title'] \
                or 'Domain for sale:' in finding['title']):
                assets_findings[asset['id']].append(finding)
    return assets_findings


def resolve_fqdn_ip(fqdn, resolver, resolver_name):
    """
    Returns the list of IPs for a fqdn
    """
    resolved_ips = list()

    try:
        resolved_ips_result = resolver.query(fqdn)
    except (NoAnswer, NoNameservers, NXDOMAIN):
        return 'No IP'
    except DNSException as dns_error:
        LOGGER.critical('DNS error with %s resolver when resolving %s: %s', resolver_name, fqdn, dns_error)
        return 'DNS error'

    for ip_address in resolved_ips_result:
        resolved_ips.append(str(ip_address))

    resolved_ips.sort()

    if resolved_ips:
        return resolved_ips[0]

    return 'No IP'


def fqdn_ip(fqdn):
    """
    Returns the list of IPs for a fqdn
    """
    resolvers = dict()
    resolvers['local'] = dict()
    resolvers['private'] = dict()

    local_resolver = Resolver()
    local_resolver.timeout = 2
    local_resolver.lifetime = 2
    resolvers['local']['resolver'] = local_resolver

    private_resolver = Resolver()
    private_resolver.timeout = 2
    private_resolver.lifetime = 2
    private_resolver.nameservers = settings.PRIVATE_DNS_RESOLVERS
    resolvers['private']['resolver'] = private_resolver

    for resolver_name in resolvers:
        resolvers[resolver_name]['result'] = resolve_fqdn_ip(
            fqdn,
            resolvers[resolver_name]['resolver'],
            resolver_name)

    result_quorum = dict()
    result_quorum['No IP'] = 0
    result_ip = 'No IP'
    for resolver_name in resolvers:
        if resolvers[resolver_name]['result'] == 'No IP':
            return 'No IP'
        _ip = resolvers[resolver_name]['result']
        if _ip not in result_quorum:
            result_quorum[_ip] = 1
        else:
            result_quorum[_ip] += 1
        if _ip != result_ip and result_quorum[_ip] > result_quorum[result_ip]:
            result_ip = _ip

    return result_ip


def add_finding(asset, title, criticity, test_only=False):
    """
    This function is a wrapper around PATROWL_API.add_finding
    """
    if test_only:
        LOGGER.warning('[TEST-ONLY] Add finding for asset #%s', asset['id'])
        return
    try:
        PATROWL_API.add_finding(
            title,
            title,
            'patrowl_asset_tagger',
            criticity,
            asset['id'])
    except:
        LOGGER.critical('Error during add finding for asset #%s', asset['id'])
        pass


def delete_finding(finding_id, test_only=False):
    """
    This function is a wrapper around PATROWL_API.delete_finding
    """
    if test_only:
        LOGGER.warning('[TEST-ONLY] Delete finding #%s', finding_id)
        return
    try:
        PATROWL_API.delete_finding(
            finding_id)
    except:
        LOGGER.critical('Error during delete finding #%s', finding_id)
        pass


def generate_random_codename(seed):
    """
    This function returns a random codename
    """
    random.seed(seed)
    with open('adjectives.txt', 'r') as adjectives_file:
        adjectives = adjectives_file.read()
    adjective = random.choice(adjectives.split('\n'))
    with open('animals.txt', 'r') as animals_file:
        animals = animals_file.read()
    animal = random.choice(animals.split('\n'))
    return '{} {}'.format(adjective, animal)


def update_for_sale_finding(asset, ct_findings, test_only=False):
    """
    This function update 'Domain for sale: True|False'
    """
    asset_findings = ct_findings[asset['id']]
    last_screenshot_epoch = 0
    last_screenshot_finding = None
    is_for_sale = False
    add_for_sale_finding = True
    current_for_sale_finding = None
    current_is_for_sale = False
    try:
        for finding in asset_findings:
            if 'Some domain has been screenshoted by eyewitness' in finding['title'] \
                and int(re.match('^\[([0-9]+)\]', finding['title']).group(1)) > last_screenshot_epoch:
                last_screenshot_epoch = int(re.match('^\[([0-9]+)\]', finding['title']).group(1))
                last_screenshot_finding = finding
                is_for_sale = 'Domain for sale: True' in last_screenshot_finding['description']
            elif 'Domain for sale:' in finding['title']:
                add_for_sale_finding = False
                current_for_sale_finding = finding
                current_is_for_sale = finding['title'] == 'Domain for sale: True'
    except Exception as err_msg:
        LOGGER.critical(err_msg)
        return ct_findings

    if add_for_sale_finding:
        if last_screenshot_epoch == 0 or not is_for_sale:
            LOGGER.warning('Add "Domain for sale: False" for %s', asset['name'])
            add_finding(asset, 'Domain for sale: False', 'info', test_only=test_only)
            ct_findings[asset['id']].append({'title': 'Domain for sale: False'})
            return ct_findings
        LOGGER.warning('Add "Domain for sale: True" for %s', asset['name'])
        add_finding(asset, 'Domain for sale: True', 'info', test_only=test_only)
        ct_findings[asset['id']].append({'title': 'Domain for sale: True'})
        return ct_findings

    # Do nothing
    if is_for_sale == current_is_for_sale:
        return ct_findings

    # Rename "Domain for sale" finding
    LOGGER.warning('Rename "Domain for sale: %s" for %s', is_for_sale, asset['name'])
    for i, finding in enumerate(ct_findings[asset['id']]):
        if 'Domain for sale' in finding['title']:
            ct_findings[asset['id']][i] = {
                'severity': current_for_sale_finding['severity'],
                'title': current_for_sale_finding['title'],
                'updated_at': current_for_sale_finding['updated_at'],
                'asset': asset['id']}
    delete_finding(current_for_sale_finding['id'], test_only=test_only)
    add_finding(
        asset,
        'Domain for sale: {}'.format(is_for_sale),
        current_for_sale_finding['severity'], test_only=test_only)
    ct_findings[asset['id']].append({'title': 'Domain for sale: {}'.format(is_for_sale)})

    return ct_findings

def update_ip_finding(asset, ct_findings, test_only=False):
    """
    This function update 'Current IP: xx.xx.xx.xx'
    """
    asset_findings = ct_findings[asset['id']]
    current_ip = fqdn_ip(asset['name'])
    # Abort if DNS is in error
    if current_ip == 'DNS error':
        return ct_findings
    add_current_ip_finding = True
    threat_codename = dict()
    for i, finding in enumerate(asset_findings):
        # Update 'Current IP' finding
        if 'Current IP: ' in finding['title'] \
            and finding['title'] != 'Current IP: {}'.format(current_ip):
            LOGGER.warning('Remove "Current IP" finding for %s', asset['name'])
            delete_finding(finding['id'], test_only=test_only)
            ct_findings[asset['id']][i]['title'] = 'Current IP: {}'.format(current_ip)
        elif finding['title'] == 'Current IP: {}'.format(current_ip):
            add_current_ip_finding = False
        elif 'Threat codename: ' in finding['title'] and ( \
            'id' not in threat_codename or threat_codename['id'] < finding['id']):
            threat_codename = finding

    if add_current_ip_finding:
        LOGGER.warning('Add "Current IP: %s" for %s', current_ip, asset['name'])
        add_finding(asset, 'Current IP: {}'.format(current_ip), 'info', test_only=test_only)
        ct_findings[asset['id']].append({'title': 'Current IP: {}'.format(current_ip)})


    # Check if "Threat codename" needs an update
    if threat_codename and current_ip != 'No IP':
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
                        'id': threat_codename['id'],
                        'severity': threat_codename['severity'],
                        'title': threat_codename['title'],
                        'description': threat_codename['description'],
                        'updated_at': threat_codename['updated_at'],
                        'asset': asset['id']}
            delete_finding(threat_codename['id'], test_only=test_only)
            add_finding(
                asset,
                threat_codename['title'].replace(old_ip, current_ip),
                threat_codename['severity'], test_only=test_only)
            ct_findings[asset['id']].append({'title': 'Current IP: {}'.format(current_ip)})

    return ct_findings


def update_current_threat(asset, ct_findings, test_only=False):
    """
    This function update 'Threat codename: xxxx (xx.xx.xx.xx)'
    """
    asset_findings = ct_findings[asset['id']]
    threat_codename = dict()
    threat_codename['finding'] = dict()
    threat_codename['new_finding'] = dict()
    current_ip = 'No IP'
    for finding in asset_findings:
        # Search 'Threat codename' finding
        if 'Threat codename: ' in finding['title'] and (\
            'id' not in threat_codename['finding'] or \
            threat_codename['finding']['id'] < finding['id']):
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
                and '({})'.format(current_ip) in finding['title'] \
                and ( \
                    'id' not in threat_codename['new_finding'] or \
                    threat_codename['new_finding']['id'] < finding['id']):
                threat_codename['new_finding'] = finding

    # New threat
    if not threat_codename['finding'] \
        and not threat_codename['new_finding'] \
        and current_ip != 'No IP':
        codename = generate_random_codename(current_ip)
        LOGGER.warning('New threat : "Threat codename: %s (%s)" for %s', codename, current_ip, asset['name'])
        slack_alert('New threat', 'Threat codename: {} ({})'.format(codename, current_ip), asset, test_only=test_only)
        ct_findings[asset['id']].append({
            'severity': 'high',
            'title': 'Threat codename: {} ({})'.format(codename, current_ip),
            'updated_at': datetime.now().isoformat(),
            'asset': asset['id']})
        add_finding(asset, 'Threat codename: {} ({})'.format(codename, current_ip), 'high', test_only=test_only)

    # New asset in existing threat
    elif not threat_codename['finding'] \
        and threat_codename['new_finding'] \
        and current_ip != 'No IP':
        LOGGER.warning('New asset in existing threat : "%s" for %s', threat_codename['new_finding']['title'], asset['name'])
        slack_alert('New asset in existing threat', threat_codename['new_finding']['title'], asset, test_only=test_only)
        ct_findings[asset['id']].append({
            'severity': threat_codename['new_finding']['severity'],
            'title': threat_codename['new_finding']['title'],
            'updated_at': threat_codename['new_finding']['updated_at'],
            'asset': asset['id']})
        add_finding(asset, threat_codename['new_finding']['title'], threat_codename['new_finding']['severity'], test_only=test_only)

    # Rename current threat, only if different
    elif threat_codename['finding'] \
        and threat_codename['new_finding'] \
        and current_ip != 'No IP' \
        and threat_codename['new_finding']['asset'] != asset['id'] \
        and (threat_codename['new_finding']['title'] != threat_codename['finding']['title']\
            or threat_codename['new_finding']['severity'] != threat_codename['finding']['severity']):
        LOGGER.warning('Rename current threat : "%s" for %s', threat_codename['new_finding']['title'], asset['name'])
        slack_alert('Rename current threat', threat_codename['new_finding']['title'], asset, criticity='info', test_only=test_only)
        for i, finding in enumerate(ct_findings[asset['id']]):
            if 'id' in finding and finding['id'] == threat_codename['finding']['id']:
                ct_findings[asset['id']][i] = {
                    'severity': threat_codename['new_finding']['severity'],
                    'title': threat_codename['new_finding']['title'],
                    'updated_at': threat_codename['new_finding']['updated_at'],
                    'asset': asset['id']}
        delete_finding(threat_codename['finding']['id'], test_only=test_only)
        add_finding(asset, threat_codename['new_finding']['title'], threat_codename['new_finding']['severity'], test_only=test_only)

    return ct_findings

def update_threat(asset, asset_findings, ct_findings, test_only=False):
    """
    This function updates the threat of Base and Archived assets
    """
    threat_codename = dict()
    threat_codename['finding'] = dict()
    threat_codename['new_finding'] = dict()
    current_ip = 'No IP'
    for finding in asset_findings:
        # Search 'Threat codename' finding
        if 'Threat codename: ' in finding['title'] and (\
            'id' not in threat_codename['finding'] or \
            threat_codename['finding']['id'] < finding['id']):
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
                and '({})'.format(current_ip) in finding['title'] \
                and ( \
                    'id' not in threat_codename['new_finding'] or \
                    threat_codename['new_finding']['id'] < finding['id']):
                threat_codename['new_finding'] = finding

    # New asset in existing threat
    if not threat_codename['finding'] \
        and threat_codename['new_finding'] \
        and current_ip != 'No IP':
        LOGGER.warning('New asset in existing threat : "%s" for %s', threat_codename['new_finding']['title'], asset['name'])
        slack_alert('New asset in existing threat', threat_codename['new_finding']['title'], asset, test_only=test_only)
        add_finding(asset, threat_codename['new_finding']['title'], threat_codename['new_finding']['severity'], test_only=test_only)

    # Rename current threat, only if different
    elif threat_codename['finding'] \
        and threat_codename['new_finding'] \
        and current_ip != 'No IP' \
        and threat_codename['new_finding']['asset'] != asset['id'] \
        and (threat_codename['new_finding']['title'] != threat_codename['finding']['title'] \
            or threat_codename['new_finding']['severity'] != threat_codename['finding']['severity']):
        LOGGER.warning('Rename current threat : "%s" for %s', threat_codename['new_finding']['title'], asset['name'])
        slack_alert('Rename current threat', threat_codename['new_finding']['title'], asset, criticity='info', test_only=test_only)
        delete_finding(threat_codename['finding']['id'], test_only=test_only)
        add_finding(asset, threat_codename['new_finding']['title'], threat_codename['new_finding']['severity'], test_only=test_only)


def slack_alert(threat_type, threat_title, asset, criticity='high', test_only=False):
    """
    Post report on Slack
    """
    payload = dict()
    payload['channel'] = settings.SLACK_CHANNEL
    payload['link_names'] = 1
    payload['username'] = settings.PAT_SLACK_USERNAME
    payload['icon_emoji'] = settings.PAT_SLACK_ICON_EMOJI

    attachments = dict()
    attachments['pretext'] = '{} - {}'.format(threat_type, threat_title)
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


def main(test_only=False):
    """
    Main function
    """
    if not os.path.exists('adjectives.txt') or not os.path.exists('animals.txt'):
        LOGGER.critical('You need both adjectives.txt and animals.txt')
        sys.exit(1)

    current_threats_group_id, archived_threats_group_id = get_group_ids()

    base_assets = get_assets(settings.PAT_GROUP_ID)
    if current_threats_group_id is None or archived_threats_group_id is None:
        LOGGER.critical('run Patrowl Asset Lifecycle first')
        sys.exit(1)
    ct_assets = get_assets(current_threats_group_id)
    at_assets = get_assets(archived_threats_group_id)

    if not base_assets and not ct_assets and not at_assets:
        LOGGER.warning('no assets')
    else:
        ct_findings = get_findings(ct_assets)
        for ct_asset in ct_assets:
            ct_findings = update_for_sale_finding(ct_asset, ct_findings, test_only=test_only)
            ct_findings = update_ip_finding(ct_asset, ct_findings, test_only=test_only)
        for ct_asset in ct_assets:
            ct_findings = update_current_threat(ct_asset, ct_findings, test_only=test_only)

        base_findings = get_findings(base_assets)
        for base_asset in base_assets:
            update_for_sale_finding(base_asset, base_findings, test_only=test_only)
            update_ip_finding(base_asset, base_findings, test_only=test_only)
            update_threat(base_asset, base_findings[base_asset['id']], ct_findings, test_only=test_only)
        at_findings = get_findings(at_assets)
        for at_asset in at_assets:
            update_for_sale_finding(at_asset, at_findings, test_only=test_only)
            update_ip_finding(at_asset, at_findings, test_only=test_only)
            update_threat(at_asset, at_findings[at_asset['id']], ct_findings, test_only=test_only)


if __name__ == '__main__':
    DEBUG = len(sys.argv) > 1 and sys.argv[1] == '--test-only'
    main(test_only=DEBUG)
