from .redis import Redis
from utils.credential_campaign import record_credential_validation, wait_before_attempt
from utils.db import DB
from utils.output import Output


def bruteforce_worker(target, timeout, delay, jitter, state):
    password = target['b_secret']
    username = target.get('b_username', 'N/A')
    scanner = Redis(target['hostname'], target['port'], timeout)
    state.begin_attempt(target)
    try:
        if not state.claim_attempt(target, None, username):
            return
        wait_before_attempt(delay, jitter)
        success, _ = scanner.auth(password)
        record_credential_validation(target, service='redis', username=username, secret=password, status='success' if success else 'failure', url=scanner.url())
        if not success:
            return
        state.mark_success(target, None, username)
        Output.event('authentication', 'Redis password accepted', target=scanner.url(), severity='success', status='success', data={'protocol': 'redis', 'secret_type': 'password'}, sensitive=True)
        DB.insert_credential({'host': target['hostname'], 'port': target['port'], 'service': 'redis', 'url': scanner.url(), 'type': 'password', 'username': username, 'password': password})
    except Exception:
        record_credential_validation(target, service='redis', username=username, secret=password, status='error', url=scanner.url())
    finally:
        try:
            scanner.disconnect()
        except Exception:
            pass
        state.complete_attempt(target)
