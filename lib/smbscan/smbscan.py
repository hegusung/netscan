import os.path
import impacket
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

                if '\\' in creds['username']:
                    creds['domain'] = creds['username'].split('\\')[0]
                    creds['username'] = creds['username'].split('\\')[1]

                if 'password' in creds:
                    try:
                        success, is_admin = smbscan.auth(domain=creds['domain'], username=creds['username'], password=creds['password'])
                        Output.write({'target': smbscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and password {password}'.format(**creds)})
                    except AuthFailure as e:
                        Output.write({'target': smbscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and password {password}: %s'.format(**creds) % str(e)})
                        return
                elif 'hash' in creds:
                    try:
                        success, is_admin = smbscan.auth(domain=creds['domain'], username=creds['username'], hash=creds['hash'])
                        Output.write({'target': smbscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and hash {hash}'.format(**creds)})
                    except AuthFailure as e:
                        Output.write({'target': smbscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and hash {hash}: %s'.format(**creds) % str(e)})
                        return
                else:
                    try:
                        success, is_admin = smbscan.auth(domain=creds['domain'], username=creds['username'], password='')
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
                output = "SAM hashes:\n"
                try:
                    entries = smbscan.dump_sam()
                    for entry in entries:
                        output += " "*60+"- %s %s\n" % (entry['username'].ljust(30), entry['hash'])
                    Output.write({'target': smbscan.url(), 'message': output})
                except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': smbscan.url(), 'message': 'SAM dump: Access denied'})
                    else:
                        raise e
            if 'lsa' in actions:
                output = "LSA secrets:\n"
                try:
                    entries = smbscan.dump_lsa()
                    for entry in entries:
                        output += " "*60+"- %s\n" % (entry['secret'],)
                    Output.write({'target': smbscan.url(), 'message': output})
                except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': smbscan.url(), 'message': 'LSA dump: Access denied'})
                    else:
                        raise e
            if 'users' in actions:
                Output.write({'target': smbscan.url(), 'message': 'Users:'})
                try:
                    entries = smbscan.enum_users()
                    for entry in entries:
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        Output.write({'target': smbscan.url(), 'message': '(%d) %s   %s  [%s]' % (entry['uid'], user.ljust(30), entry['fullname'].ljust(30), ','.join(entry['tags']))})
                except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': smbscan.url(), 'message': 'Enum users: Access denied'})
                    else:
                        raise e
            if 'groups' in actions:
                Output.write({'target': smbscan.url(), 'message': 'Groups:'})
                try:
                    entries = smbscan.enum_groups()
                    for entry in entries:
                        group = '%s\\%s' % (entry['domain'], entry['groupname'])
                        Output.write({'target': smbscan.url(), 'message': '(%d) %s   %s' % (entry['uid'], group.ljust(30), entry['admin_comment'])})
                except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': smbscan.url(), 'message': 'Enum groups: Access denied'})
                    else:
                        raise e
            if 'admins' in actions:
                Output.write({'target': smbscan.url(), 'message': 'Administrators:'})
                try:
                    entries = smbscan.enum_admins()
                    for entry in entries:
                        admin = '%s\\%s' % (entry['domain'], entry['name'])
                        Output.write({'target': smbscan.url(), 'message': '- %s (%s)' % (admin.ljust(30), entry['type'])})
                except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': smbscan.url(), 'message': 'Enum admins: Access denied'})
                    else:
                        raise e
            if 'passpol' in actions:
                try:
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
                except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': smbscan.url(), 'message': 'Enum password policy: Access denied'})
                    else:
                        raise e
            if 'loggedin' in actions:
                Output.write({'target': smbscan.url(), 'message': 'Logged in users:'})
                try:
                    entries = smbscan.enum_loggedin()
                    for entry in entries:
                        Output.write({'target': smbscan.url(), 'message': 'Logged in: %s\\%s' % (entry['domain'], entry['username'])})
                except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': smbscan.url(), 'message': 'Enum logged in: Access denied'})
                    else:
                        raise e
            if 'session' in actions:
                Output.write({'target': smbscan.url(), 'message': 'Sessions:'})
                try:
                    entries = smbscan.enum_sessions()
                    for entry in entries:
                        Output.write({'target': smbscan.url(), 'message': 'Session: %s' % (entry,)})
                except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': smbscan.url(), 'message': 'Enum sessions: Access denied'})
                    else:
                        raise e
            if 'rid_brute' in actions:
                Output.write({'target': smbscan.url(), 'message': 'Users discovered via RID bruteforce:'})
                try:
                    entries = smbscan.rid_bruteforce(actions['rid_brute']['start'], actions['rid_brute']['end'])
                    for entry in entries:
                        user = '%s\\%s' % (entry['domain'], entry['name'])
                        Output.write({'target': smbscan.url(), 'message': '- %s (%s)' % (user.ljust(30), entry['type'])})
                except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': smbscan.url(), 'message': 'RID brutefroce: Access denied'})
                    else:
                        raise e


    except ConnectionResetError:
        Output.write({'target': smbscan.url(), 'message': 'Connection reset by target'})
    except TypeError as e:
        if 'ConnectionResetError' in str(e):
            Output.write({'target': smbscan.url(), 'message': 'Connection reset by target'})
        else:
            Output.write({'target': smbscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    except Exception as e:
        Output.write({'target': smbscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        smbscan.disconnect()

