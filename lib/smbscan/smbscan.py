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
                    shares += " "*60+"- %s %s %s\n" % (share_info['name'].ljust(15), ", ".join(share_info['access']).ljust(20), share_info['remark'])
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
                            contents += " "*60+"- %s %s\n" % (content['name'].ljust(30), sizeof_fmt(content['size']))
                        else:
                            contents += " "*60+"- %s\n" % (content['name'].ljust(30),)
                    Output.write({'target': smbscan.url(), 'message': contents})
            if 'command' in actions:
                output = smbscan.exec(actions['command']['command'], exec_method=actions['command']['method'], get_output=True)
                if output:
                    Output.write({'target': smbscan.url(), 'message': 'Executed command \'%s\':\n%s' % (actions['command']['command'], output)})
                else:
                    Output.write({'target': smbscan.url(), 'message': 'Failed to execute command %s' % (actions['command']['command'],)})
            if 'sam' in actions:
                entries = smbscan.dump_sam()
                output = "SAM hashes:\n"
                for entry in entries:
                    output += " "*60+"- %s %s\n" % (entry['username'].ljust(30), entry['hash'])
                Output.write({'target': smbscan.url(), 'message': output})
            if 'lsa' in actions:
                entries = smbscan.dump_lsa()
                output = "LSA secrets:\n"
                for entry in entries:
                    output += " "*60+"- %s\n" % (entry['secret'],)
                Output.write({'target': smbscan.url(), 'message': output})
            if 'users' in actions:
                entries = smbscan.enum_users()
                Output.write({'target': smbscan.url(), 'message': 'Users:'})
                for entry in entries:
                    user = '%s\\%s' % (entry['domain'], entry['username'])
                    Output.write({'target': smbscan.url(), 'message': '(%d) %s   %s' % (entry['uid'], user.ljust(30), entry['fullname'])})
            if 'groups' in actions:
                entries = smbscan.enum_groups()
                Output.write({'target': smbscan.url(), 'message': 'Groups:'})
                for entry in entries:
                    group = '%s\\%s' % (entry['domain'], entry['groupname'])
                    Output.write({'target': smbscan.url(), 'message': '(%d) %s   %s' % (entry['uid'], group.ljust(30), entry['admin_comment'])})
            if 'admins' in actions:
                entries = smbscan.enum_admins()
                Output.write({'target': smbscan.url(), 'message': 'Administrators:'})
                for entry in entries:
                    admin = '%s\\%s' % (entry['domain'], entry['name'])
                    Output.write({'target': smbscan.url(), 'message': '- %s (%s)' % (admin.ljust(30), entry['type'])})
            if 'passpol' in actions:
                password_policy = smbscan.enum_password_policy()
                output = "Password policy:\n"
                output += " "*60+"- Complexity:       %s\n" % ("Enabled" if password_policy['complexity'] == 1 else "Disabled",)
                output += " "*60+"- Minimum length:   %d\n" % password_policy['minimum_length']
                output += " "*60+"- History:          last %d passwords\n" % password_policy['history_length']
                output += " "*60+"- Maximum age:      %s\n" % password_policy['maximum_age']
                output += " "*60+"- Minimum age:      %s\n" % password_policy['minimum_age']
                output += " "*60+"- Lock threshold:   %s\n" % (str(password_policy['lock_threshold']) if password_policy['lock_threshold'] != 0 else "Disabled",)
                if password_policy['lock_threshold'] != 0:
                    output += " "*60+"- Lock duration:    %s\n" % password_policy['lock_duration']

                Output.write({'target': smbscan.url(), 'message': output})
            if 'loggedin' in actions:
                entries = smbscan.enum_loggedin()
                Output.write({'target': smbscan.url(), 'message': 'Logged in users:'})
                for entry in entries:
                    Output.write({'target': smbscan.url(), 'message': 'Logged in: %s\\%s' % (entry['domain'], entry['username'])})
            if 'session' in actions:
                entries = smbscan.enum_sessions()
                Output.write({'target': smbscan.url(), 'message': 'Sessions:'})
                for entry in entries:
                    Output.write({'target': smbscan.url(), 'message': 'Session: %s' % (entry,)})

    except Exception as e:
        Output.write({'target': smbscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        smbscan.disconnect()

