import os.path
from time import sleep
import socket
import traceback
import struct
import copy
import logging
import paramiko

from .telnet import Telnet
from .telnet_bruteforce import *

from utils.output import Output
from utils.dispatch import dispatch

def telnetscan_worker(target, actions, creds, timeout):
    try:

        telnet = Telnet(target['hostname'], target['port'], timeout)

        banner = telnet.connect()
        Output.write({'target': telnet.url(), 'message': 'Telnet: %s' % banner})

        if 'username' in creds and 'password' in creds:

            success = telnet.auth(creds['username'], creds['password'])
            if success:
                Output.write({'target': telnet.url(), 'message': 'Successful authentication with username %s and password %s' % (creds['username'], creds['password'])})

                if 'command' in actions:
                    output = "Command '%s':\n" % actions['command']['command']
                    output += telnet.execute(actions['command']['command'])
                    Output.write({'target': target['hostname'], 'message': output})
            else:
                Output.write({'target': telnet.url(), 'message': 'Authentication failure with username %s and password %s' % (creds['username'], creds['password'])})

        if 'bruteforce' in actions:
            if 'username_file' in actions['bruteforce'] != None:
                Output.write({'target': telnet.url(), 'message': 'Starting bruteforce:'})

                username_file = actions['bruteforce']['username_file']
                password_file = actions['bruteforce']['password_file'] if 'password_file' in actions['bruteforce'] else None
                bruteforce_workers = actions['bruteforce']['workers']

                # The generator will provide a username:password_list couple
                gen = bruteforce_generator(target, username_file, password_file)
                gen_size = bruteforce_generator_count(target, username_file, password_file)

                args = (timeout,)
                dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])

    except ConnectionRefusedError:
        pass
    except Exception as e:
        Output.write({'target': telnet.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        telnet.disconnect()

