import os.path
from time import sleep
import socket
import traceback
import struct
import copy

from .winrm import WinRMScan
from .winrm_bruteforce import bruteforce_worker, bruteforce_generator, bruteforce_generator_count
from utils.credential_campaign import CampaignState

from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB

def winrmscan_worker(target, actions, creds, timeout):
    winrmscan = None
    creds = creds.copy()
    # Process creds
    if 'username' in creds and '\\' in creds['username']:
        creds['domain'] = creds['username'].split('\\')[0]
        creds['username'] = creds['username'].split('\\')[1]

    try:
        domain = creds['domain'] if 'domain' in creds else None
        username = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None
        hash = creds['hash'] if 'hash' in creds else None
        winrmscan = WinRMScan(
            target['hostname'],
            target['port'],
            timeout,
            ssl=target.get('ssl', False) or target['port'] == 5986,
        )

        if domain:
            user = "%s@%s" % (username, domain)
        else:
            user = username

        if username and (password or hash):
            success = winrmscan.auth(domain, user, password, hash)
            if success:
                DB.insert_port({
                    'host': target['hostname'],
                    'port': target['port'],
                    'protocol': 'tcp',
                    'service': 'winrm',
                })
                if password:
                    creds_str = "%s and password %s" % (user, password)
                    DB.insert_credential({
                        'host': target['hostname'],
                        'port': target['port'],
                        'service': 'winrm',
                        'url': winrmscan.url(),
                        'type': 'password',
                        'username': user,
                        'password': password,
                    })
                else:
                    creds_str = "%s and hash %s" % (user, hash)
                    DB.insert_credential({
                        'host': target['hostname'],
                        'port': target['port'],
                        'service': 'winrm',
                        'url': winrmscan.url(),
                        'type': 'hash',
                        'username': user,
                        'format': 'ntlm',
                        'hash': hash,
                    })
                Output.success({'target': winrmscan.url(), 'message': 'Successful authentication with credentials %s' % creds_str})

                if 'command' in actions:
                    output = "Command '%s':\n" % actions['command']['command']
                    output += winrmscan.execute(actions['command']['command'], get_output=True)
                    Output.write({'target': winrmscan.url(), 'message': output})
            else:
                if password:
                    creds_str = "%s and password %s" % (user, password)
                else:
                    creds_str = "%s and hash %s" % (user, hash)
                Output.minor({'target': winrmscan.url(), 'message': 'Authentication failure with credentials %s' % creds_str})

        if 'bruteforce' in actions and actions['bruteforce'].get('username_file') is not None:
            Output.highlight({'target': winrmscan.url(), 'message': 'Starting bruteforce:'})
            username_file = actions['bruteforce']['username_file']
            password_file = actions['bruteforce'].get('password_file')
            generator = bruteforce_generator(
                target,
                username_file,
                password_file,
                simple_bruteforce=actions['bruteforce'].get('simple', False),
                strategy=actions['bruteforce']['strategy'],
                domain=domain,
                max_attempts_per_account=actions['bruteforce']['max_attempts_per_account'],
            )
            generator_size = bruteforce_generator_count(
                target,
                username_file,
                password_file,
                default_domain=domain,
                strategy=actions['bruteforce']['strategy'],
                simple=actions['bruteforce'].get('simple', False),
                max_attempts_per_account=actions['bruteforce']['max_attempts_per_account'],
            )
            state = CampaignState(
                continue_on_success=actions['bruteforce']['continue_on_success']
            )
            dispatch(
                generator,
                generator_size,
                bruteforce_worker,
                (
                    timeout,
                    actions['bruteforce']['delay'],
                    actions['bruteforce']['jitter'],
                    state,
                ),
                workers=actions['bruteforce']['workers'],
                process=False,
                pg_name=target['hostname'],
            )

    except Exception as e:
        target_url = winrmscan.url() if winrmscan is not None else target['hostname']
        Output.write({'target': target_url, 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        if winrmscan is not None:
            winrmscan.disconnect()

