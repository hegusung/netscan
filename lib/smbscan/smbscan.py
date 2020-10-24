import os.path
from time import sleep
import socket
import traceback
import struct

from .smb import SMBScan, AuthFailure, sizeof_fmt

from utils.output import Output

"""
Lot of code here taken from CME, @byt3bl33d3r did an awesome job with impacket
"""

def smbscan_worker(target, actions, creds, timeout):
    try:
        smbscan = SMBScan(target['hostname'], target['port'], timeout)

        if smbscan.connect():
            # We are against a SMB server

            # Gather info
            smb_info = smbscan.get_server_info()
            smb_info['target'] = smbscan.url()
            smb_info['message_type'] = 'smb'
            Output.write(smb_info)

            smbscan.disconnect()

            # Start new connection
            smbscan.connect()

            # Authenticate
            if not 'username' in creds:
                return
            else:
                if not 'domain' in creds:
                    creds['domain'] = 'WORKGROUP'

                if 'password' in creds:
                    try:
                        success, is_admin = smbscan.auth(domain=creds['username'], username=creds['username'], password=creds['password'])
                        Output.write({'target': smbscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and password {password}'.format(**creds)})
                    except AuthFailure as e:
                        Output.write({'target': smbscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and password {password}: %s'.format(**creds) % str(e)})
                        return
                elif 'hash' in creds:
                    try:
                        success, is_admin = smbscan.auth(domain=creds['username'], username=creds['username'], hash=creds['hash'])
                        Output.write({'target': smbscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and hash {hash}'.format(**creds)})
                    except AuthFailure as e:
                        Output.write({'target': smbscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and hash {hash}: %s'.format(**creds) % str(e)})
                        return
                else:
                    try:
                        success, is_admin = smbscan.auth(domain=creds['username'], username=creds['username'], password='')
                        Output.write({'target': smbscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and no password'.format(**creds)})
                    except AuthFailure as e:
                        Output.write({'target': smbscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and no password: %s'.format(**creds) % str(e)})
                        return

                if is_admin:
                    Output.write({'target': smbscan.url(), 'message': 'Administrative privileges with credentials {domain}\\{username}'.format(**creds)})

            # Authenticated, now perform actions
            share_list = []
            if 'list_shares' in actions:
                shares = "Shares:\n"
                for share_info in smbscan.list_shares():
                    shares += " "*80+"- %s %s %s\n" % (share_info['name'].ljust(15), ", ".join(share_info['access']).ljust(20), share_info['remark'])
                    share_list.append(share_info['name'])
                Output.write({'target': smbscan.url(), 'message': shares})
            if 'list' in actions:
                if not 'share' in actions['list']:
                    if len(share_list) == 0:
                        for share_info in smbscan.list_shares():
                            share_list.append(share_info['name'])
                else:
                    share_list = [actions['list']['share']]

                for share in share_list:
                    contents = "Content of share %s:\n" % share
                    for content in smbscan.list_content(path="\\", share=share, recurse=actions['list']['recurse']):
                        if 'size' in content:
                            contents += " "*80+"- %s %s\n" % (content['name'].ljust(30), sizeof_fmt(content['size']))
                        else:
                            contents += " "*80+"- %s\n" % (content['name'].ljust(30),)
                    Output.write({'target': smbscan.url(), 'message': contents})

    except Exception as e:
        Output.write({'target': smbscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        smbscan.disconnect()

