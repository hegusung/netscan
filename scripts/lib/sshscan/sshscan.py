import os.path
from time import sleep
import socket
import traceback
import struct
import copy
import logging
import paramiko

from .ssh import SSH
from utils.output import Output
from utils.db import DB
from utils.modulemanager import ModuleManager

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

ssh_modules = ModuleManager('lib/sshscan/modules')

def sshscan_worker(target, actions, creds, timeout):
    try:

        ssh = SSH(target['hostname'], target['port'], timeout)

        version = ssh.get_version()
        if not version:
            return
        Output.write({'target': ssh.url(), 'message': '%s' % version})
        DB.insert_port({
            'host': target['hostname'],
            'port': target['port'],
            'protocol': 'tcp',
            'service': 'ssh',
            'version': version,
        })

        if 'username' in creds and ('password' in creds or 'key_file' in creds):

            if 'password' in creds:
                success = ssh.auth(creds['username'], creds['password'])
            elif 'key_file' in creds:
                success = ssh.auth_key(creds['username'], creds['key_file'])
            if success:
                secret_type = 'password' if 'password' in creds else 'ssh_key'
                Output.event(
                    'authentication',
                    'Successful authentication for username %s' % creds['username'],
                    target=ssh.url(), severity='success', status='success',
                    data={'protocol': 'ssh', 'username': creds['username'],
                          'secret_type': secret_type},
                    sensitive=True,
                )
                cred_info = {
                    'host': target['hostname'],
                    'port': target['port'],
                    'service': 'ssh',
                    'url': ssh.url(),
                    'type': 'password',
                    'username': creds['username'],
                    'password': creds['password'] if 'password' in creds else creds['key_file'],
                }
                DB.insert_credential(cred_info)


                if 'command' in actions:
                    output = "Command '%s':\n" % actions['command']['command']
                    output += ssh.execute(actions['command']['command'])
                    Output.write({'target': target['hostname'], 'message': output})
            else:
                Output.event(
                    'authentication',
                    'Authentication failure for username %s' % creds['username'],
                    target=ssh.url(), severity='debug', status='failure',
                    data={'protocol': 'ssh', 'username': creds['username']},
                    sensitive=True,
                )

        if 'modules' in actions:
            ssh_modules.execute_modules(actions['modules']['modules'], (target, actions['modules']['args'], creds, timeout))

    except paramiko.AuthenticationException as e:
        Output.event(
            'authentication',
            'Authentication failure for username %s' % creds.get('username', ''),
            target=ssh.url(), severity='debug', status='failure',
            data={'protocol': 'ssh', 'username': creds.get('username')},
            sensitive=True,
        )
    except ValueError as e:
        Output.minor({'target': ssh.url(), 'message': "Authentication failure because of crypto failure: %s" % str(e)})
    except paramiko.SSHException as e:
        pass
    except socket.error:
        pass
    except Exception as e:
        Output.write({'target': ssh.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        ssh.disconnect()

