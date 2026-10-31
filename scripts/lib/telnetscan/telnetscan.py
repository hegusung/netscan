import os.path
from time import sleep
import socket
import traceback
import struct
import copy
import logging
import paramiko

from .telnet import Telnet
from utils.output import Output
from utils.db import DB

def telnetscan_worker(target, actions, creds, timeout):
    try:

        telnet = Telnet(target['hostname'], target['port'], timeout)

        banner = telnet.connect()
        Output.write({'target': telnet.url(), 'message': 'Telnet: %s' % banner})
        DB.insert_port({
            'host': target['hostname'],
            'port': target['port'],
            'protocol': 'tcp',
            'service': 'telnet',
            'service_info': {
                'banner': banner,
            }
        })

        if 'username' in creds and 'password' in creds:

            success = telnet.auth(creds['username'], creds['password'])
            if success:
                Output.success({'target': telnet.url(), 'message': 'Successful authentication with username %s and password %s' % (creds['username'], creds['password'])})
                cred_info = {
                    'host': target['hostname'],
                    'port': target['port'],
                    'service': 'telnet',
                    'url': telnet.url(),
                    'type': 'password',
                    'username': creds['username'],
                    'password': creds['password'],
                }
                DB.insert_credential(cred_info)

                if 'command' in actions:
                    output = "Command '%s':\n" % actions['command']['command']
                    output += telnet.execute(actions['command']['command'])
                    Output.highlight({'target': target['hostname'], 'message': output})
            else:
                Output.minor({'target': telnet.url(), 'message': 'Authentication failure with username %s and password %s' % (creds['username'], creds['password'])})

    except OSError:
        pass
    except ConnectionRefusedError:
        pass
    except Exception as e:
        Output.write({'target': telnet.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        try:
            telnet.disconnect()
        except:
            pass

