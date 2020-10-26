import os.path
from time import sleep
import socket
import traceback
import struct
import copy

from .winrm import WinRMScan

from utils.output import Output

def winrmscan_worker(target, actions, creds, timeout):
    # Process creds
    if 'username' in creds and '\\' in creds['username']:
        creds['domain'] = creds['username'].split('\\')[0]
        creds['username'] = creds['username'].split('\\')[1]

    try:
        domain = creds['domain'] if 'domain' in creds else None
        username = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None
        hash = creds['hash'] if 'hash' in creds else None
        winrmscan = WinRMScan(target['hostname'], timeout)

        success = winrmscan.auth(domain, username, password, hash)
        if success: 
            if domain:
                user = "%s\\%s" % (domain, username)
            else:
                user = username
            if password:
                creds_str = "%s and password %s" % (user, password)
            else:
                creds_str = "%s and hash %s" % (user, hash)
            Output.write({'target': target['hostname'], 'message': 'Successful authentication with credentials %s' % creds_str})

            if 'command' in actions:
                output = "Command '%s':\n" % actions['command']['command']
                output += winrmscan.execute(actions['command']['command'], get_output=True)
                Output.write({'target': target['hostname'], 'message': output})

    except Exception as e:
        Output.write({'target': target['hostname'], 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        winrmscan.disconnect()

