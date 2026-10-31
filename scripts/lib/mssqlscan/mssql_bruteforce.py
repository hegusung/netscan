from .mssql import MSSQLScan
from utils.credential_campaign import credential_attempt_count, iter_credential_attempts, record_credential_validation, wait_before_attempt
from utils.db import DB
from utils.output import Output
from utils.utils import AuthFailure


def bruteforce_worker(target, timeout, delay, jitter, state):
    domain, username, password = target.get('b_domain'), target['b_username'], target['b_secret']
    scanner = MSSQLScan(target['hostname'], target['port'], timeout)
    state.begin_attempt(target)
    try:
        if not state.claim_attempt(target, domain, username):
            return
        wait_before_attempt(delay, jitter)
        if not scanner.connect():
            return
        success, is_admin = scanner.auth(domain, username, password, None)
        record_credential_validation(target, service='mssql', domain=domain, username=username, secret=password, status='success' if success else 'failure', admin=is_admin, url=scanner.url())
        if not success:
            return
        state.mark_success(target, domain, username)
        Output.event('authentication', 'Authentication success for account %s' % username, target=scanner.url(), severity='success', status='success', data={'protocol': 'mssql', 'domain': domain, 'username': username, 'secret_type': 'password'}, sensitive=True)
        credential = {'type': 'password', 'username': username, 'password': password}
        if domain not in [None, 'WORKGROUP']:
            credential['domain'] = domain
            DB.insert_domain_credential(credential)
        else:
            credential.update({'host': target['hostname'], 'port': target['port'], 'service': 'mssql', 'url': scanner.url()})
            DB.insert_credential(credential)
        if is_admin:
            Output.event('privilege', 'MSSQL sysadmin privileges for account %s' % username, target=scanner.url(), severity='high', status='admin', data={'protocol': 'mssql', 'domain': domain, 'username': username}, sensitive=True)
    except AuthFailure:
        record_credential_validation(target, service='mssql', domain=domain, username=username, secret=password, status='failure', url=scanner.url())
    except Exception:
        record_credential_validation(target, service='mssql', domain=domain, username=username, secret=password, status='error', url=scanner.url())
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
