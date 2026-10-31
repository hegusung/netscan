import os.path
from time import sleep
import socket
import traceback
import struct
import copy

from .winrm import WinRMScan
from utils.output import Output
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
                Output.event(
                    'authentication', 'Successful authentication for account %s' % user,
                    target=winrmscan.url(), severity='success', status='success',
                    data={'protocol': 'winrm', 'username': user,
                          'secret_type': 'password' if password else 'ntlm'},
                    sensitive=True,
                )

                if 'command' in actions:
                    output = "Command '%s':\n" % actions['command']['command']
                    output += winrmscan.execute(actions['command']['command'], get_output=True)
                    Output.write({'target': winrmscan.url(), 'message': output})
            else:
                Output.event(
                    'authentication', 'Authentication failure for account %s' % user,
                    target=winrmscan.url(), severity='debug', status='failure',
                    data={'protocol': 'winrm', 'username': user,
                          'secret_type': 'password' if password else 'ntlm'},
                    sensitive=True,
                )

    except Exception as e:
        target_url = winrmscan.url() if winrmscan is not None else target['hostname']
        Output.write({'target': target_url, 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        if winrmscan is not None:
            winrmscan.disconnect()

