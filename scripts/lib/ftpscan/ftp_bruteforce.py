import time

from .ftp import FTPScan
from utils.credential_campaign import credential_attempt_count, iter_credential_attempts, record_credential_validation, wait_before_attempt
from utils.db import DB
from utils.output import Output


def bruteforce_worker(target, timeout, delay, jitter, state):
    username, password = target['b_username'], target['b_secret']
    scanner = None
    state.begin_attempt(target)
    try:
        if not state.claim_attempt(target, None, username):
            return
        wait_before_attempt(delay, jitter)
        scanner = FTPScan(target['hostname'], target['port'], timeout)
        scanner.connect()
        success = scanner.auth(username, password)
        record_credential_validation(target, service='ftp', username=username, secret=password, status='success' if success else 'failure', url=scanner.url())
        if not success:
            return
        state.mark_success(target, None, username)
        Output.event('authentication', 'Authentication success for account %s' % username, target=scanner.url(), severity='success', status='success', data={'protocol': 'ftp', 'username': username, 'secret_type': 'password'}, sensitive=True)
        DB.insert_credential({'host': target['hostname'], 'port': target['port'], 'service': 'ftp', 'url': scanner.url(), 'type': 'password', 'username': username, 'password': password})
        DB.insert_vulnerability({'host': target['hostname'], 'port': target['port'], 'service': 'ftp', 'url': scanner.url(), 'name': 'Default or predictable credentials on FTP service', 'description': 'FTP accepts a password from the authorized credential campaign for account %s' % username})
    except Exception:
        record_credential_validation(target, service='ftp', username=username, secret=password, status='error', url=scanner.url() if scanner is not None else 'ftp://%s:%s' % (target['hostname'], target['port']))
        time.sleep(1)
    finally:
        if scanner is not None:
            try:
                scanner.disconnect()
            except Exception:
                pass
        state.complete_attempt(target)


def bruteforce_generator(target, username_file, password_file, simple_bruteforce=False, **options):
    return iter_credential_attempts(target, username_file, password_file, simple=simple_bruteforce, **options)


def bruteforce_generator_count(target, username_file, password_file, **options):
    return credential_attempt_count(target, username_file, password_file, **options)
