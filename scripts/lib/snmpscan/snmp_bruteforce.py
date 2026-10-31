import pysnmp.error

from .snmpscan import SNMP, SNMPError, SNMPTimeout
from utils.credential_campaign import record_credential_validation, wait_before_attempt
from utils.db import DB
from utils.output import Output


def bruteforce_worker(target, timeout, delay, jitter, state):
    community = target['b_secret']
    username = target.get('b_username', 'N/A')
    scanner = SNMP(target['hostname'], target['port'], timeout)
    state.begin_attempt(target)
    try:
        if not state.claim_attempt(target, None, username):
            return
        wait_before_attempt(delay, jitter)
        scanner.request_v2(community=community)
        state.mark_success(target, None, username)
        record_credential_validation(target, service='snmp', username=username, secret=community, secret_kind='community', status='success', url=scanner.url())
        Output.event('authentication', 'SNMP community accepted', target=scanner.url(), severity='success', status='success', data={'protocol': 'snmp', 'secret_type': 'community'}, sensitive=True)
        DB.insert_credential({'host': target['hostname'], 'port': target['port'], 'service': 'snmp', 'url': scanner.url(), 'type': 'password', 'username': username, 'password': community, '_secret_kind': 'community'})
    except SNMPTimeout:
        record_credential_validation(target, service='snmp', username=username, secret=community, secret_kind='community', status='failure', url=scanner.url())
    except (SNMPError, pysnmp.error.PySnmpError):
        record_credential_validation(target, service='snmp', username=username, secret=community, secret_kind='community', status='error', url=scanner.url())
    finally:
        state.complete_attempt(target)
