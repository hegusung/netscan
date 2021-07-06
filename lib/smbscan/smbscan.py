import os.path
import impacket
from time import sleep
import socket
import traceback
import struct

from .smb import SMBScan, AuthFailure, sizeof_fmt
from .smb_bruteforce import bruteforce_worker, bruteforce_generator, bruteforce_generator_count

from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB
from utils.modulemanager import ModuleManager

"""
Lot of code here taken from CME, @byt3bl33d3r did an awesome job with impacket
"""

smb_modules = ModuleManager('lib/smbscan/modules')

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
            DB.insert_port({
                'hostname': target['hostname'],
                'port': 445,
                'protocol': 'tcp',
                'service': 'smb',
                'version': smb_info['server_os'],
                'service_info': {
                    'os': smb_info['server_os'],
                    'domain': smb_info['domain'],
                    'hostname': smb_info['hostname'],
                    'signing': smb_info['signing'],
                }
            })
            DB.insert_domain_host({
                'hostname_ip': target['hostname'],
                'os': smb_info['server_os'],
                'domain': smb_info['domain'],
                'hostname': smb_info['hostname'],
            })

            smbscan.disconnect()

            # Start new connection
            smbscan.connect()

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
                        success, is_admin = smbscan.auth(domain=creds['domain'], username=creds['username'], password=creds['password'])
                        Output.success({'target': smbscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and password {password}'.format(**creds)})
                        if not 'domain' in creds or creds['domain'] in [None, 'WORKGROUP']:
                            # local account
                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'smb',
                                'url': smbscan.url(),
                                'type': 'password',
                                'username': creds['username'],
                                'password': creds['password'],
                            }
                            DB.insert_credential(cred_info)

                        else:
                            # domain account 
                            cred_info = {
                                'domain': creds['domain'],
                                'username': creds['username'],
                                'password': creds['password'],
                            }
                            DB.insert_domain_user(cred_info)

                            pass
                    except AuthFailure as e:
                        Output.minor({'target': smbscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and password {password}: %s'.format(**creds) % str(e)})
                elif 'hash' in creds:
                    try:
                        success, is_admin = smbscan.auth(domain=creds['domain'], username=creds['username'], hash=creds['hash'])
                        Output.success({'target': smbscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and hash {hash}'.format(**creds)})
                        if not 'domain' in creds or creds['domain'] in [None, 'WORKGROUP']:
                            # local account
                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'smb',
                                'url': smbscan.url(),
                                'type': 'hash',
                                'username': creds['username'],
                                'format': 'ntlm',
                                'hash': creds['hash'],
                            }
                            DB.insert_credential(cred_info)

                        else:
                            # domain account 
                            cred_info = {
                                'domain': creds['domain'],
                                'username': creds['username'],
                                'hash': creds['hash'],
                            }
                            DB.insert_domain_user(cred_info)

                    except AuthFailure as e:
                        Output.minor({'target': smbscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and hash {hash}: %s'.format(**creds) % str(e)})
                else:
                    try:
                        success, is_admin = smbscan.auth(domain=creds['domain'], username=creds['username'], password='')
                        Output.success({'target': smbscan.url(), 'message': 'Successful authentication with credentials {domain}\\{username} and no password'.format(**creds)})
                    except AuthFailure as e:
                        Output.minor({'target': smbscan.url(), 'message': 'Authentication failure with credentials {domain}\\{username} and no password: %s'.format(**creds) % str(e)})

                if is_admin:
                    Output.major({'target': smbscan.url(), 'message': 'Administrative privileges with credentials {domain}\\{username}'.format(**creds)})

                    if 'domain' in creds and not creds['domain'] in [None, 'WORKGROUP']:
                            # domain account 
                            cred_info = {
                                'domain': creds['domain'],
                                'username': creds['username'],
                                'admin_of': target['hostname'],
                            }
                            DB.insert_domain_user(cred_info)


            if success:
                # Authenticated, now perform actions
                share_list = []
                if 'list_shares' in actions:
                    shares = "Shares:\n"
                    try:
                        for share_info in smbscan.list_shares():
                            shares += " "*60+"- %s %s %s\n" % (share_info['name'].ljust(15), ", ".join(share_info['access']).ljust(20), share_info['remark'])
                            share_list.append(share_info['name'])

                            db_info = {
                                'hostname': target['hostname'],
                                'port': 445,
                                'url': smbscan.url(),
                                'share': share_info['name'],
                                'service': 'smb',
                                'path': '/',
                                'access': share_info['access'],
                                'comment': share_info['remark'],
                            }
                            DB.insert_content(db_info)

                        Output.highlight({'target': smbscan.url(), 'message': shares})


                    except impacket.nmb.NetBIOSError:
                        # Connection reset
                        Output.error({'target': smbscan.url(), 'message': 'List shares: Access denied'})
                    except impacket.smbconnection.SessionError as e:
                        if 'STATUS_ACCESS_DENIED' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'List shares: Access denied'})
                        else:
                            raise e
                if 'list' in actions:
                    try:
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
                                    contents += " "*60+"- %s     %s\n" % (content['name'].ljust(30), sizeof_fmt(content['size']))
                                else:
                                    contents += " "*60+"- %s\n" % (content['name'].ljust(30),)

                                db_info = {
                                    'hostname': target['hostname'],
                                    'port': 445,
                                    'url': smbscan.url(),
                                    'share': share,
                                    'service': 'smb',
                                    'path': content['name'].replace('\\', '/'),
                                }
                                if 'size' in content:
                                    db_info['size'] = content['size']
                                DB.insert_content(db_info)
                            Output.highlight({'target': smbscan.url(), 'message': contents})
                    except impacket.smbconnection.SessionError as e:
                        if 'STATUS_ACCESS_DENIED' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'List share contents: Access denied'})
                        else:
                            raise e
                if 'command' in actions:
                    output = smbscan.exec(actions['command']['command'], exec_method=actions['command']['method'], get_output=True)
                    if output:
                        Output.highlight({'target': smbscan.url(), 'message': 'Executed command \'%s\':\n%s' % (actions['command']['command'], output)})
                    else:
                        Output.error({'target': smbscan.url(), 'message': 'Failed to execute command %s' % (actions['command']['command'],)})
                if 'sam' in actions:
                    output = "SAM hashes:\n"
                    try:
                        entries = smbscan.dump_sam()
                        for entry in entries:
                            output += " "*60+"- %s %s\n" % (entry['username'].ljust(30), entry['hash'])

                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'smb',
                                'url': smbscan.url(),
                                'type': 'hash',
                                'format': 'ntlm',
                                'username': entry['username'],
                                'hash': entry['hash'],
                            }
                            DB.insert_credential(cred_info)

                        Output.highlight({'target': smbscan.url(), 'message': output})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'SAM dump: Access denied'})
                        else:
                            raise e
                if 'lsa' in actions:
                    output = "LSA secrets:\n"
                    try:
                        entries = smbscan.dump_lsa()
                        for entry in entries:
                            output += " "*60+"- %s\n" % (entry['secret'],)
                        Output.highlight({'target': smbscan.url(), 'message': output})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'LSA dump: Access denied'})
                        else:
                            raise e
                if 'users' in actions:
                    Output.write({'target': smbscan.url(), 'message': 'Users:'})
                    try:
                        entries = smbscan.enum_users()
                        for entry in entries:
                            user = '%s\\%s' % (entry['domain'], entry['username'])
                            Output.highlight({'target': smbscan.url(), 'message': '(%d) %s   %s  [%s]' % (entry['uid'], user.ljust(30), entry['fullname'].ljust(30), ','.join(entry['tags']))})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum users: Access denied'})
                        else:
                            raise e
                if 'groups' in actions:
                    Output.write({'target': smbscan.url(), 'message': 'Groups:'})
                    try:
                        entries = smbscan.enum_groups()
                        for entry in entries:
                            group = '%s\\%s' % (entry['domain'], entry['groupname'])
                            Output.highlight({'target': smbscan.url(), 'message': '(%d) %s   %s' % (entry['uid'], group.ljust(30), entry['admin_comment'])})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum groups: Access denied'})
                        else:
                            raise e
                if 'admins' in actions:
                    Output.write({'target': smbscan.url(), 'message': 'Administrators:'})
                    try:
                        entries = smbscan.enum_admins()
                        for entry in entries:
                            admin = '%s\\%s' % (entry['domain'], entry['name'])
                            Output.highlight({'target': smbscan.url(), 'message': '- %s (%s)' % (admin.ljust(30), entry['type'])})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum admins: Access denied'})
                        else:
                            raise e
                if 'apps' in actions:
                    output = smbscan.exec("wmic product get name,version,installdate", exec_method=None, get_output=True)
                    if output:
                        msg = "Applications:\n"
                        app_items = output.encode().decode('utf16').split('\n')[1:]
                        for app in app_items:
                            items = app.split()

                            if len(items) == 0:
                                continue

                            installdate = items[0]
                            version = items[-1]
                            name = ' '.join(items[1:-1])

                            msg += "- %s %s (%s)\n" % (name.ljust(30), version.ljust(15), installdate)

                            db_info = {
                                'hostname': target['hostname'],
                                'port': 445,
                                'url': smbscan.url(),
                                'name': name,
                                'version': version,
                                'installdate': installdate,
                            }
                            DB.insert_application(db_info)

                        Output.highlight({'target': smbscan.url(), 'message': msg})
                    else:
                        Output.error({'target': smbscan.url(), 'message': 'Failed to dump applications'})
                if 'processes' in actions:
                    Output.highlight({'target': smbscan.url(), 'message': 'Processes:'})
                    try:
                        entries = smbscan.enum_processes()
                        for entry in entries:
                            if entry['pid'] != None:
                                proc = '[%d] %s' % (entry['pid'], entry['name'])
                                user = '%s\\%s' % (entry['domain'], entry['user'])
                                Output.highlight({'target': smbscan.url(), 'message': '%s   %s' % (proc.ljust(30), user)})
                    except Exception as e:
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

                        Output.highlight({'target': smbscan.url(), 'message': output})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum password policy: Access denied'})
                        else:
                            raise e
                if 'loggedin' in actions:
                    Output.write({'target': smbscan.url(), 'message': 'Logged in users:'})
                    try:
                        entries = smbscan.enum_loggedin()
                        for entry in entries:
                            Output.highlight({'target': smbscan.url(), 'message': 'Logged in: %s\\%s' % (entry['domain'], entry['username'])})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum logged in: Access denied'})
                        else:
                            raise e
                if 'sessions' in actions:
                    Output.write({'target': smbscan.url(), 'message': 'Sessions:'})
                    try:
                        entries = smbscan.enum_sessions()
                        for entry in entries:
                            Output.highlight({'target': smbscan.url(), 'message': 'Session: %s' % (entry,)})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum sessions: Access denied'})
                        else:
                            raise e
                if 'rid_brute' in actions:
                    Output.write({'target': smbscan.url(), 'message': 'Users discovered via RID bruteforce:'})
                    try:
                        entries = smbscan.rid_bruteforce(actions['rid_brute']['start'], actions['rid_brute']['end'])
                        for entry in entries:
                            user = '%s\\%s' % (entry['domain'], entry['name'])
                            Output.highlight({'target': smbscan.url(), 'message': '- %s (%s)' % (user.ljust(30), entry['type'])})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'RID brutefroce: Access denied'})
                        else:
                            raise e

            if 'modules' in actions:
                smb_modules.execute_modules(actions['modules']['modules'], (target, actions['modules']['args'], creds, timeout))
            if 'bruteforce' in actions:
                if 'username_file' in actions['bruteforce'] != None:
                    Output.highlight({'target': smbscan.url(), 'message': 'Starting bruteforce:'})

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
                if 'username_file' in actions['simple_bruteforce'] != None:
                    Output.highlight({'target': smbscan.url(), 'message': 'Starting simple bruteforce:'})

                    if 'domain' in creds:
                        domain = creds['domain']
                    else:
                        domain = 'WORKGROUP'
                    username_file = actions['simple_bruteforce']['username_file']
                    bruteforce_workers = actions['simple_bruteforce']['workers']

                    # The generator will provide a username:password_list couple
                    gen = bruteforce_generator(target, domain, username_file, None, simple_bruteforce=True)
                    gen_size = bruteforce_generator_count(target, domain, username_file, None)

                    args = (timeout,)
                    dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])

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

