from .mongo import Mongo
from utils.credential_campaign import credential_attempt_count, iter_credential_attempts, record_credential_validation, wait_before_attempt
from utils.db import DB
from utils.output import Output


def bruteforce_worker(target, timeout, delay, jitter, state):
    username, password = target['b_username'], target['b_secret']
    scanner = Mongo(target['hostname'], target['port'], timeout)
    state.begin_attempt(target)
    try:
        if not state.claim_attempt(target, None, username):
            return
        wait_before_attempt(delay, jitter)
        success, _ = scanner.auth(username, password, database=target['database'])
        record_credential_validation(target, service='mongo', username=username, secret=password, status='success' if success else 'failure', url=scanner.url())
        if not success:
            return
        state.mark_success(target, None, username)
        Output.event('authentication', 'Authentication success for account %s' % username, target=scanner.url(), severity='success', status='success', data={'protocol': 'mongo', 'username': username, 'database': target['database'], 'secret_type': 'password'}, sensitive=True)
        DB.insert_credential({'host': target['hostname'], 'port': target['port'], 'service': 'mongo', 'url': scanner.url(), 'type': 'password', 'username': username, 'password': password})
    except Exception:
        record_credential_validation(target, service='mongo', username=username, secret=password, status='error', url=scanner.url())
    finally:
        try:
            scanner.disconnect()
        except Exception:
            pass
        state.complete_attempt(target)


def bruteforce_generator(target, username_file, password_file, simple_bruteforce=False, **options):
    return iter_credential_attempts(target, username_file, password_file, simple=simple_bruteforce, **options)


def bruteforce_generator_count(target, username_file, password_file, **options):
    return credential_attempt_count(target, username_file, password_file, **options)
