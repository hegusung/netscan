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


def rdpscan_worker(target, actions, creds, timeout):
    try:
        rdpscan = RDP(target['hostname'], target['port'], timeout)

        rdp_info = rdpscan.get_certificate_info()

        Output.write({'target': rdpscan.url(), 'message': '%s' % rdp_info['hostname']})

        """
        if rdpscan.connect():
            # We are against a SMB server

            # Gather info
            rdp_info = rdpscan.get_server_info()
            rdp_info['target'] = rdpscan.url()
            rdp_info['message_type'] = 'rdp'
            Output.write(rdp_info)

            rdpscan.disconnect()

            # Start new connection
            rdpscan.connect()

            success = False
            is_admin = False
            # Authenticate
            if not 'username' in creds:
                pass
            else:
                if not 'domain' in creds:
                    creds['domain'] = 'WORKGROUP'

                if '\\' in creds['username']:
                    creds['domain'] = creds['username'].split('\\')[0]
                    creds['username'] = creds['username'].split('\\')[1]

                if 'password' in creds:
                    try:
                        success, is_admin = rdpscan.auth(domain=creds['domain'], username=creds['username'], password=creds['password'])
                        Output.write({'target': rdpscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and password {password}'.format(**creds)})
                    except AuthFailure as e:
                        Output.write({'target': rdpscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and password {password}: %s'.format(**creds) % str(e)})
                elif 'hash' in creds:
                    try:
                        success, is_admin = rdpscan.auth(domain=creds['domain'], username=creds['username'], hash=creds['hash'])
                        Output.write({'target': rdpscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and hash {hash}'.format(**creds)})
                    except AuthFailure as e:
                        Output.write({'target': rdpscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and hash {hash}: %s'.format(**creds) % str(e)})
                else:
                    try:
                        success, is_admin = rdpscan.auth(domain=creds['domain'], username=creds['username'], password='')
                        Output.write({'target': rdpscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and no password'.format(**creds)})
                    except AuthFailure as e:
                        Output.write({'target': rdpscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and no password: %s'.format(**creds) % str(e)})

                if is_admin:
                    Output.write({'target': rdpscan.url(), 'message': 'Administrative privileges with credentials {domain}\\{username}'.format(**creds)})

            if success:
                # Authenticated, now perform actions
        """

    except ssl.SSLError as e:
        pass
    except ConnectionRefusedError:
        pass
    except OSError:
        pass
    except ConnectionResetError:
        Output.write({'target': rdpscan.url(), 'message': 'Connection reset by target'})
    except Exception as e:
        Output.write({'target': rdpscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        rdpscan.disconnect()

