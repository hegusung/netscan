import socket
import paramiko
from .ssh import SSH
from utils.credential_campaign import (
    credential_attempt_count,
    iter_credential_attempts,
    record_credential_validation,
    wait_before_attempt,
)
from utils.output import Output
from utils.utils import AuthFailure
from utils.db import DB

def bruteforce_worker(target, timeout, delay, jitter, state):
    username = target['b_username']
    password = target['b_secret']
    domain = target.get('b_domain')
    state.begin_attempt(target)
    try:
        if not state.claim_attempt(target, domain, username):
            return
        wait_before_attempt(delay, jitter)
        ssh = SSH(target['hostname'], target['port'], timeout)
        try:
            if not ssh.auth(username, password):
                record_credential_validation(
                    target, service='ssh', username=username, secret=password,
                    status='failure', url=ssh.url(),
                )
                return
            state.mark_success(target, domain, username)
            record_credential_validation(
                target, service='ssh', username=username, secret=password,
                status='success', url=ssh.url(),
            )
            Output.event(
                'authentication', 'Authentication success for account %s' % username,
                target=ssh.url(), severity='success', status='success',
                data={'protocol': 'ssh', 'username': username, 'secret_type': 'password'},
                sensitive=True,
            )
            DB.insert_credential({
                'host': target['hostname'], 'port': target['port'], 'service': 'ssh',
                'url': ssh.url(), 'type': 'password', 'username': username,
                'password': password,
            })
            DB.insert_vulnerability({
                'host': target['hostname'], 'port': target['port'], 'service': 'ssh',
                'url': ssh.url(), 'name': 'Default or predictable credentials on SSH service',
                'description': 'SSH accepts a password from the supplied authorized credential campaign for account %s' % username,
            })
        except paramiko.AuthenticationException:
            record_credential_validation(
                target, service='ssh', username=username, secret=password,
                status='failure', url=ssh.url(),
            )
        except ValueError:
            record_credential_validation(
                target, service='ssh', username=username, secret=password,
                status='error', url=ssh.url(),
            )
        except paramiko.SSHException:
            record_credential_validation(
                target, service='ssh', username=username, secret=password,
                status='error', url=ssh.url(),
            )
            Output.write({'target': ssh.url(), 'message': 'Server overloaded, try reducing amount of workers'})
        except socket.error:
            record_credential_validation(
                target, service='ssh', username=username, secret=password,
                status='error', url=ssh.url(),
            )
        except Exception:
            record_credential_validation(
                target, service='ssh', username=username, secret=password,
                status='error', url=ssh.url(),
            )
        finally:
            try:
                ssh.disconnect()
            except Exception:
                pass
    finally:
        state.complete_attempt(target)

def bruteforce_generator(
    target, username_file, password_file, simple_bruteforce=False,
    strategy='bruteforce', max_attempts_per_account=None,
):
    return iter_credential_attempts(
        target, username_file, password_file, strategy=strategy,
        simple=simple_bruteforce,
        max_attempts_per_account=max_attempts_per_account,
    )

def bruteforce_generator_count(target, username_file, password_file, **options):
    return credential_attempt_count(target, username_file, password_file, **options)
