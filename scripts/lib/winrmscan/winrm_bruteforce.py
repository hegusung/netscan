import copy
from time import sleep

from .winrm import WinRMScan
from utils.db import DB
from utils.output import Output


def _principal(domain, username):
    return f"{username}@{domain}" if domain else username


def bruteforce_worker(target, domain, timeout, bruteforce_delay):
    username = target['b_username']
    user = _principal(domain, username)

    for password in target['b_password_list']:
        sleep(bruteforce_delay)
        scanner = WinRMScan(
            target['hostname'],
            target['port'],
            timeout,
            ssl=target.get('ssl', False) or target['port'] == 5986,
        )
        try:
            if not scanner.auth(domain, user, password, None):
                continue

            Output.success({
                'target': scanner.url(),
                'message': 'Authentication success with credentials %s and password %s' % (user, password),
            })
            DB.insert_port({
                'host': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'winrm',
            })
            DB.insert_credential({
                'host': target['hostname'],
                'port': target['port'],
                'service': 'winrm',
                'url': scanner.url(),
                'type': 'password',
                'username': user,
                'password': password,
            })
            DB.insert_vulnerability({
                'host': target['hostname'],
                'port': target['port'],
                'service': 'winrm',
                'url': scanner.url(),
                'name': 'Default or predictable credentials on WinRM service',
                'description': 'WinRM accepts a password from the supplied authorized credential campaign for account %s' % user,
            })
            break
        finally:
            scanner.disconnect()


def bruteforce_generator(target, username_file, password_file, simple_bruteforce=False):
    passwords = []
    if password_file is not None:
        with open(password_file) as password_stream:
            passwords = [line.strip() for line in password_stream if line.strip()]

    with open(username_file) as username_stream:
        for line in username_stream:
            entry = line.strip()
            if not entry:
                continue

            if ':' in entry:
                username, inline_password = entry.split(':', 1)
                selected_passwords = [inline_password]
            else:
                username = entry
                selected_passwords = [username] if simple_bruteforce else passwords

            generated = copy.copy(target)
            generated['b_username'] = username
            generated['b_password_list'] = selected_passwords
            yield generated


def bruteforce_generator_count(target, username_file, password_file=None):
    with open(username_file) as username_stream:
        return sum(1 for line in username_stream if line.strip())
