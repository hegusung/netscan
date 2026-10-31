from .smb import SMBScan
from utils.credential_campaign import (
    credential_attempt_count,
    iter_credential_attempts,
    wait_before_attempt,
)
from utils.output import Output
from utils.utils import AuthFailure
from utils.db import DB

def _bruteforce_worker(target, delay, jitter, timeout, state, use_hash=False):
        smbscan = None
        secret = target['b_secret']
        domain = target.get('b_domain')
        username = target['b_username']
        state.begin_attempt(target)
        try:
            if not state.claim_attempt(target, domain, username):
                return
            wait_before_attempt(delay, jitter)
            smbscan = SMBScan(target['hostname'], target['port'], timeout)
            if not smbscan.connect():
                Output.write({'target': smbscan.url(), 'message': 'Unable to connect to SMB server'})
                return
            if use_hash:
                success, is_admin = smbscan.auth(domain=domain, username=username, hash=secret)
            else:
                success, is_admin = smbscan.auth(domain, username, secret)
            if not success:
                return
            state.mark_success(target, domain, username)
            Output.event(
                'authentication', 'Authentication success for account %s\\%s' % (domain, username),
                target=smbscan.url(), severity='success', status='success',
                data={'protocol': 'smb', 'domain': domain, 'username': username,
                      'secret_type': 'ntlm' if use_hash else 'password'},
                sensitive=True,
            )
            if domain in [None, 'WORKGROUP']:
                cred_info = {
                    'host': target['hostname'],
                    'port': target['port'],
                    'service': 'smb',
                    'url': smbscan.url(),
                    'type': 'hash' if use_hash else 'password',
                    'username': username,
                }
                if use_hash:
                    cred_info.update({'format': 'ntlm', 'hash': secret})
                else:
                    cred_info['password'] = secret
                DB.insert_credential(cred_info)
            else:
                cred_info = {
                    'domain': domain,
                    'username': username,
                    'type': 'hash' if use_hash else 'password',
                }
                if use_hash:
                    cred_info.update({'format': 'ntlm', 'hash': secret})
                else:
                    cred_info['password'] = secret
                DB.insert_domain_credential(cred_info)
            if is_admin:
                Output.event(
                    'privilege', 'Administrative privileges for account %s\\%s' % (domain, username),
                    target=smbscan.url(), severity='high', status='admin',
                    data={'protocol': 'smb', 'domain': domain, 'username': username},
                    sensitive=True,
                )
        except AuthFailure as exc:
            if str(exc) == "STATUS_ACCOUNT_LOCKED_OUT":
                state.mark_locked(target, domain, username)
                Output.event(
                    'authentication', 'Account locked out: %s\\%s' % (domain, username),
                    target=smbscan.url(), severity='warning', status='locked',
                    data={'protocol': 'smb', 'domain': domain, 'username': username},
                    sensitive=True,
                )
            elif str(exc) == "STATUS_LOGON_FAILURE":
                pass
            else:
                Output.write({'target': smbscan.url(), 'message': 'Authentication failure for %s\\%s: %s' % (domain, username, str(exc))})
        finally:
            if smbscan is not None:
                try:
                    smbscan.disconnect()
                except Exception:
                    pass
            state.complete_attempt(target)


def bruteforce_worker(target, delay, jitter, timeout, state):
    return _bruteforce_worker(target, delay, jitter, timeout, state, use_hash=False)

def bruteforce_ntlm_worker(target, delay, jitter, timeout, state):
    return _bruteforce_worker(target, delay, jitter, timeout, state, use_hash=True)


def bruteforce_generator(
    target, domain, username_file, password_file, simple_bruteforce=False,
    strategy='bruteforce', secret_kind='password', max_attempts_per_account=None,
):
    return iter_credential_attempts(
        target, username_file, password_file, default_domain=domain,
        strategy=strategy, secret_kind=secret_kind, simple=simple_bruteforce,
        max_attempts_per_account=max_attempts_per_account,
    )

def bruteforce_generator_count(target, domain, username_file, password_file, **options):
    return credential_attempt_count(
        target, username_file, password_file, default_domain=domain, **options
    )
