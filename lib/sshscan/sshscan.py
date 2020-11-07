import os.path
from time import sleep
import socket
import traceback
import struct
import copy
import logging
import paramiko

from .ssh import SSH
from .ssh_bruteforce import *

from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

def sshscan_worker(target, actions, creds, timeout):
    try:

        ssh = SSH(target['hostname'], target['port'], timeout)

        version = ssh.get_version()
        if not version:
            return
        Output.write({'target': ssh.url(), 'message': '%s' % version})
        DB.insert_port({
            'hostname': target['hostname'],
            'port': target['port'],
            'protocol': 'tcp',
            'service': 'ssh',
            'version': version,
        })

        if 'username' in creds and 'password' in creds:

            success = ssh.auth(creds['username'], creds['password'])
            if success:
                Output.write({'target': ssh.url(), 'message': 'Successful authentication with username %s and password %s' % (creds['username'], creds['password'])})
                cred_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'ssh',
                    'url': ssh.url(),
                    'type': 'password',
                    'username': creds['username'],
                    'password': creds['password'],
                }
                DB.insert_credential(cred_info)


                if 'command' in actions:
                    output = "Command '%s':\n" % actions['command']['command']
                    output += ssh.execute(actions['command']['command'])
                    Output.write({'target': target['hostname'], 'message': output})
            else:
                Output.write({'target': ssh.url(), 'message': 'Authentication failure with username %s and password %s' % (creds['username'], creds['password'])})

        if 'bruteforce' in actions:
            if 'username_file' in actions['bruteforce'] != None:
                Output.write({'target': ssh.url(), 'message': 'Starting bruteforce:'})

                username_file = actions['bruteforce']['username_file']
                password_file = actions['bruteforce']['password_file'] if 'password_file' in actions['bruteforce'] else None
                bruteforce_workers = actions['bruteforce']['workers']

                # The generator will provide a username:password_list couple
                gen = bruteforce_generator(target, username_file, password_file)
                gen_size = bruteforce_generator_count(target, username_file, password_file)

                args = (timeout,actions['bruteforce']['bruteforce_delay'])
                dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])

    except paramiko.AuthenticationException as e:
        Output.write({'target': ssh.url(), 'message': 'Authentication failure with username %s and password %s' % (creds['username'], creds['password'])})
    except ValueError as e:
        Output.write({'target': ssh.url(), 'message': "Authentication failure because of crypto failure: %s" % str(e)})
    except paramiko.SSHException as e:
        pass
    except socket.error:
        pass
    except Exception as e:
        Output.write({'target': ssh.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        ssh.disconnect()

