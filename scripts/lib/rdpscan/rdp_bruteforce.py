from time import sleep

from .rdp import RDP
from utils.credential_campaign import credential_attempt_count, iter_credential_attempts, record_credential_validation, wait_before_attempt
from utils.db import DB
from utils.output import Output


def bruteforce_worker(target, timeout, delay, jitter, state):
    domain, username, password = target.get('b_domain'), target['b_username'], target['b_secret']
    scanner = RDP(target['hostname'], target['port'], timeout)
    state.begin_attempt(target)
    try:
        if not state.claim_attempt(target, domain, username):
            return
        wait_before_attempt(delay, jitter)
        success = scanner.check_auth(domain, username, password)
        sleep(0.5)
        record_credential_validation(target, service='rdp', domain=domain, username=username, secret=password, status='success' if success else 'failure', url=scanner.url())
        if not success:
            return
        state.mark_success(target, domain, username)
        Output.event('authentication', 'Authentication success for account %s' % username, target=scanner.url(), severity='success', status='success', data={'protocol': 'rdp', 'domain': domain, 'username': username, 'secret_type': 'password'}, sensitive=True)
        credential = {'type': 'password', 'username': username, 'password': password}
        if domain not in [None, 'WORKGROUP']:
            credential['domain'] = domain
            DB.insert_domain_credential(credential)
        else:
            credential.update({'host': target['hostname'], 'port': target['port'], 'service': 'rdp', 'url': scanner.url()})
            DB.insert_credential(credential)
    except Exception:
        record_credential_validation(target, service='rdp', domain=domain, username=username, secret=password, status='error', url=scanner.url())
    finally:
        try:
            scanner.disconnect()
        except Exception:
            pass
        state.complete_attempt(target)


def bruteforce_generator(target, domain, username_file, password_file, simple_bruteforce=False, **options):
    return iter_credential_attempts(target, username_file, password_file, default_domain=domain, simple=simple_bruteforce, **options)


def bruteforce_generator_count(target, domain, username_file, password_file, **options):
    return credential_attempt_count(target, username_file, password_file, default_domain=domain, **options)
