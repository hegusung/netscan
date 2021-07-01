import os.path
import ssl
import impacket
from time import sleep
import socket
import traceback
import struct

from .rdp import RDP
from .rdp_bruteforce import bruteforce_worker, bruteforce_generator, bruteforce_generator_count

from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB


def rdpscan_worker(target, actions, creds, timeout):
    try:
        rdp = RDP(target['hostname'], target['port'], timeout)

        rdp_info = rdp.get_certificate_info()

        Output.write({'target': rdp.url(), 'message': '%s' % rdp_info['hostname']})
        DB.insert_port({
            'hostname': target['hostname'],
            'port': target['port'],
            'protocol': 'tcp',
            'service': 'rdp',
            'service_info': {
                'hostname': rdp_info['hostname'],
            }
        })

        if 'username' in creds:
            domain = creds['domain'] if 'domain' in creds else None
            username = creds['username']
            password = creds['password'] if 'password' in creds else None
            ntlm_hash = creds['hash'] if 'hash' in creds else None

            result = rdp.check_auth(domain, username, password, ntlm_hash)

            if domain:
                user = '%s\\%s' % (domain, username)
            else:
                user = username
            if password:
                user_secret = 'password %s' % password
            else:
                user_secret = 'hash %s' % ntlm_hash
            if result:
                Output.success({'target': rdp.url(), 'message': 'Successful authentication with credentials %s and %s' % (user, user_secret)})
                if domain in [None, 'WORKGROUP']:
                    # local account
                    if password:
                        cred_info = {
                            'hostname': target['hostname'],
                            'port': target['port'],
                            'service': 'rdp',
                            'url': rdp.url(),
                            'type': 'password',
                            'username': username,
                            'password': password,
                        }
                    else:
                        cred_info = {
                            'hostname': target['hostname'],
                            'port': target['port'],
                            'service': 'rdp',
                            'url': rdp.url(),
                            'type': 'hash',
                            'format': 'ntlm',
                            'username': username,
                            'hash': ntlm_hash,
                        }
                    DB.insert_credential(cred_info)

                else:
                    # domain account 
                    if password:
                        cred_info = {
                            'domain': creds['domain'],
                            'username': creds['username'],
                            'password': creds['password'],
                        }
                        DB.insert_domain_user(cred_info)
                    else:
                        cred_info = {
                            'domain': creds['domain'],
                            'username': creds['username'],
                            'hash': creds['hash'],
                        }
                        DB.insert_domain_user(cred_info)

            else:
                Output.minor({'target': rdp.url(), 'message': 'Authentication failure with credentials %s and %s' % (user, user_secret)})

        if 'bruteforce' in actions:
            if 'username_file' in actions['bruteforce'] != None:
                Output.highlight({'target': rdp.url(), 'message': 'Starting bruteforce:'})

                if 'domain' in creds:
                    domain = creds['domain']
                else:
                    domain = 'WORKGROUP'
                username_file = actions['bruteforce']['username_file']
                password_file = actions['bruteforce']['password_file'] if 'password_file' in actions['bruteforce'] else None
                bruteforce_workers = actions['bruteforce']['workers']

                # The generator will provide a username:password_list couple
                gen = bruteforce_generator(target, domain, username_file, password_file)
                gen_size = bruteforce_generator_count(target, domain, username_file, password_file)

                args = (timeout,)
                dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])
        if 'simple_bruteforce' in actions:
            if 'username_file' in actions['bruteforce'] != None:
                Output.highlight({'target': rdp.url(), 'message': 'Starting simple bruteforce:'})

                if 'domain' in creds:
                    domain = creds['domain']
                else:
                    domain = 'WORKGROUP'
                username_file = actions['bruteforce']['username_file']
                bruteforce_workers = actions['bruteforce']['workers']

                # The generator will provide a username:password_list couple
                gen = bruteforce_generator(target, domain, username_file, None, simple_bruteforce=True)
                gen_size = bruteforce_generator_count(target, domain, username_file, password_file)

                args = (timeout,)
                dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])

    except ssl.SSLError as e:
        pass
    except ConnectionRefusedError:
        pass
    except OSError:
        pass
    except ConnectionResetError:
        Output.write({'target': rdp.url(), 'message': 'Connection reset by target'})
    except Exception as e:
        Output.write({'target': rdp.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        rdp.disconnect()

