from .winrm import WinRMScan
from utils.credential_campaign import (
    CampaignState,
    credential_attempt_count,
    iter_credential_attempts,
    record_credential_validation,
    wait_before_attempt,
)
from utils.db import DB
from utils.output import Output


def _principal(domain, username):
    return f"{username}@{domain}" if domain else username


def bruteforce_worker(target, timeout, delay, jitter, state):
    domain = target.get('b_domain')
    username = target['b_username']
    password = target['b_secret']
    user = _principal(domain, username)
    state.begin_attempt(target)
    try:
        if not state.claim_attempt(target, domain, username):
            return
        wait_before_attempt(delay, jitter)
        scanner = WinRMScan(
            target['hostname'], target['port'], timeout,
            ssl=target.get('ssl', False) or target['port'] == 5986,
        )
        try:
            if not scanner.auth(domain, user, password, None):
                record_credential_validation(
                    target, service='winrm', domain=domain, username=username,
                    secret=password, status='failure', url=scanner.url(),
                )
                Output.event(
                    'authentication', 'Authentication failure for account %s' % user,
                    target=scanner.url(), severity='debug', status='failure',
                    data={'protocol': 'winrm', 'username': user, 'secret_type': 'password'},
                    sensitive=True,
                )
                return

            state.mark_success(target, domain, username)
            record_credential_validation(
                target, service='winrm', domain=domain, username=username,
                secret=password, status='success', url=scanner.url(),
            )
            Output.event(
                'authentication', 'Authentication success for account %s' % user,
                target=scanner.url(), severity='success', status='success',
                data={'protocol': 'winrm', 'username': user, 'secret_type': 'password'},
                sensitive=True,
            )
            DB.insert_port({
                'host': target['hostname'], 'port': target['port'],
                'protocol': 'tcp', 'service': 'winrm',
            })
            DB.insert_credential({
                'host': target['hostname'], 'port': target['port'],
                'service': 'winrm', 'url': scanner.url(), 'type': 'password',
                'username': user, 'password': password,
            })
            DB.insert_vulnerability({
                'host': target['hostname'], 'port': target['port'],
                'service': 'winrm', 'url': scanner.url(),
                'name': 'Default or predictable credentials on WinRM service',
                'description': 'WinRM accepts a password from the supplied authorized credential campaign for account %s' % user,
            })
        finally:
            scanner.disconnect()
    finally:
        state.complete_attempt(target)


def bruteforce_generator(
    target, username_file, password_file, simple_bruteforce=False,
    strategy='bruteforce', domain=None, max_attempts_per_account=None,
):
    return iter_credential_attempts(
        target, username_file, password_file, default_domain=domain,
        strategy=strategy, simple=simple_bruteforce,
        max_attempts_per_account=max_attempts_per_account,
    )


def bruteforce_generator_count(target, username_file, password_file=None, **options):
    return credential_attempt_count(target, username_file, password_file, **options)
