from time import sleep

from .vnc import VNC
from utils.credential_campaign import record_credential_validation, wait_before_attempt
from utils.db import DB
from utils.output import Output


def bruteforce_worker(target, timeout, delay, jitter, state):
    password = target['b_secret']
    username = target.get('b_username', 'N/A')
    scanner = VNC(target['hostname'], target['port'], timeout)
    state.begin_attempt(target)
    try:
        if not state.claim_attempt(target, None, username):
            return
        wait_before_attempt(delay, jitter)
        scanner.connect()
        code, _ = scanner.auth('VNC Authentication', password=password)
        success = code == 0
        record_credential_validation(target, service='vnc', username=username, secret=password, status='success' if success else 'failure', url=scanner.url())
        if not success:
            return
        state.mark_success(target, None, username)
        Output.event('authentication', 'VNC password accepted', target=scanner.url(), severity='success', status='success', data={'protocol': 'vnc', 'secret_type': 'password'}, sensitive=True)
        DB.insert_credential({'host': target['hostname'], 'port': target['port'], 'service': 'vnc', 'url': scanner.url(), 'type': 'password', 'username': username, 'password': password})
        sleep(0.5)
    except Exception:
        record_credential_validation(target, service='vnc', username=username, secret=password, status='error', url=scanner.url())
    finally:
        try:
            scanner.disconnect()
        except Exception:
            pass
        state.complete_attempt(target)
