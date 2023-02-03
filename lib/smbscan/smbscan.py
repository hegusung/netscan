import os.path
import impacket
from time import sleep
import socket
import traceback
import struct
import re

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

windows_build = re.compile("Windows \S+ Build (\d+)")

def smbscan_worker(target, actions, creds, timeout):
    try:
        smbscan = SMBScan(target['hostname'], target['port'], timeout)

        if smbscan.connect():
            # We are against a SMB server

            # Gather info
            smb_info = smbscan.get_server_info()

            # Get build version
            if smbscan.smbv1:
                # Get build version via SMB2
                smbv2 = SMBScan(target['hostname'], target['port'], timeout, use_smbv1=False)
                if smbv2.connect():
                    smb_info_v2 = smbv2.get_server_info()
                    v2_os = smb_info_v2['server_os']
                else:
                    v2_os = ""
            else:
                v2_os = smb_info['server_os']

            m = windows_build.match(v2_os)
            if m:
                build = m.group(1)
            else:
                build = "Unknown"

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
                    'smbv1': smb_info['smbv1'],
                    'build': build,
                }
            })
            DB.insert_domain_host({
                'hostname_ip': target['hostname'],
                'os': smb_info['server_os'],
                'domain': smb_info['domain'],
                'hostname': smb_info['hostname'],
            })

            ip = target['hostname']
            if smb_info['signing'] == False:
                Output.vuln({'target': 'smb://%s:445' % (ip,), 'message': 'SMB protocol is not signed, vulnerable to relay attacks'})

                vuln_info = {
                    'hostname': ip,
                    'port': 445,
                    'service': 'smb',
                    'url': 'smb://%s' % (ip,),
                    'name': 'SMB Signing disabled',
                    'description': 'Server smb://%s SMB signature is not enabled, vulnerable to relay attacks' % (ip,),
                }
                DB.insert_vulnerability(vuln_info)

            if smb_info['smbv1'] == True:
                Output.vuln({'target': 'smb://%s:445' % (ip,), 'message': 'SMBv1 protocol is deprecated'})

                vuln_info = {
                    'hostname': ip,
                    'port': 445,
                    'service': 'smb',
                    'url': 'smb://%s' % (ip,),
                    'name': 'SMBv1 enabled',
                    'description': 'Server smb://%s SMBv1 protocol is enabled, prone to vulnerabilities' % (ip,),
                }
                DB.insert_vulnerability(vuln_info)

            smbscan.disconnect()

            # Start new connection
            smbscan.connect()

            success = False
            is_admin = False
            # Authenticate
            if 'kerberos' in creds:
                try:
                    ticket = os.environ['KRB5CCNAME']

                    from impacket.krb5.ccache import CCache
                    ccache = CCache.loadFile(ticket)
                    domain = ccache.principal.realm['data'].decode('utf-8')
                    principal = 'cifs/%s@%s' % (smb_info['hostname'].upper(), domain.upper())
                    ticket_creds = ccache.getCredential(principal)
                    if ticket_creds is not None:
                        user = ticket_creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                    elif len(ccache.principal.components) > 0:
                        user = ccache.principal.components[0]['data'].decode('utf-8')

                    creds['username'] = user
                    creds['domain'] = domain

                    dc_ip = creds['dc_ip'] if 'dc_ip' in creds else None

                    success, is_admin = smbscan.kerberos_auth(dc_ip=dc_ip)

                    Output.success({'target': smbscan.url(), 'message': 'Successful authentication from kerberos ticket %s (%s\\%s)' % (ticket, domain, user)})

                    if is_admin:
                        Output.major({'target': smbscan.url(), 'message': 'Administrative privileges with kerberos ticket %s (%s\\%s)' % (ticket, domain, user)})

                        if 'domain' in creds and not creds['domain'] in [None, 'WORKGROUP']:
                                # domain account 
                                cred_info = {
                                    'domain': domain,
                                    'username': user,
                                    'admin_of': target['hostname'],
                                }
                                DB.insert_domain_user(cred_info)

                except AuthFailure as e:
                    Output.minor({'target': smbscan.url(), 'message': 'Authentication failure with kerberos ticket %s (%s\\%s)' % (ticket, domain, user)})

            elif 'username' in creds:
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
                                'type': 'password',
                                'password': creds['password'],
                            }
                            DB.insert_domain_credential(cred_info)

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
                                'type': 'hash',
                                'format': 'ntlm',
                                'hash': creds['hash'],
                            }
                            DB.insert_domain_credential(cred_info)

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
                                'url': smbscan.url("/%s" % share_info['name']),
                                'share': share_info['name'],
                                'service': 'smb',
                                'path': '/',
                                'account': "%s\\%s" % (creds['domain'], creds['username']),
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
                        if 'path' in target:
                            share_name = target['path'].split('/')[1]
                            share_list = [share_name]
                        elif 'share' in actions['list']:
                            share_list = [actions['list']['share']]
                        else:
                            if len(share_list) == 0:
                                for share_info in smbscan.list_shares():
                                    share_list.append(share_info['name'])

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
                                    'url': smbscan.url("/%s" % share),
                                    'share': share,
                                    'service': 'smb',
                                    'path': content['name'].replace('\\', '/'),
                                    'account': "%s\\%s" % (creds['domain'], creds['username']),
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
                    host_info = {
                        'hostname_ip': target['hostname'],
                        'os': smb_info['server_os'],
                        'domain': smb_info['domain'],
                        'hostname': smb_info['hostname'],
                    }
                    new_info = False

                    Output.write({'target': smbscan.url(), 'message': 'Administrators:'})
                    try:
                        entries = smbscan.dump_admins()
                        for admin_group in entries:
                            Output.highlight({'target': smbscan.url(), 'message': '- %s' % (admin_group,)})
                            for sid in entries[admin_group]:
                                Output.highlight({'target': smbscan.url(), 'message': '   - %s' % (sid,)})

                            host_info[admin_group] = entries[admin_group]
                            new_info = True
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum admins: Access denied'})
                        else:
                            raise e

                    if new_info:
                        DB.insert_domain_host(host_info)

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
                        if password_policy:
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
                if 'sessions' in actions:
                    host_info = {
                        'hostname_ip': target['hostname'],
                        'os': smb_info['server_os'],
                        'domain': smb_info['domain'],
                        'hostname': smb_info['hostname'],
                    }
                    new_info = False

                    Output.write({'target': smbscan.url(), 'message': 'Logged in users:'})
                    try:
                        privileged_sessions = []
                        entries = smbscan.enum_loggedin()
                        for entry in entries:
                            Output.highlight({'target': smbscan.url(), 'message': 'Logged in: %s\\%s' % (entry['domain'], entry['username'])})
                            privileged_sessions.append({
                                'domain': entry['domain'],
                                'username': entry['username'],
                            })

                        host_info['privileged_sessions'] = privileged_sessions
                        new_info = True
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum logged in: Access denied'})
                        else:
                            raise e

                    Output.write({'target': smbscan.url(), 'message': 'Sessions:'})
                    try:
                        sessions = []
                        entries = smbscan.enum_sessions()
                        for entry in entries:
                            Output.highlight({'target': smbscan.url(), 'message': 'Session: %s' % (entry,)})

                            sessions.append({
                                'username': entry['username'],
                            })

                        host_info['host_sessions'] = sessions
                        new_info = True
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum sessions: Access denied'})
                        else:
                            raise e

                    Output.write({'target': smbscan.url(), 'message': 'Registry Sessions:'})
                    try:
                        registry_sessions = []
                        entries = smbscan.dump_registry_sessions()
                        for entry in entries:
                            Output.highlight({'target': smbscan.url(), 'message': 'Registry Session: %s' % (entry,)})

                            registry_sessions.append({
                                'sid': entry,
                            })

                        host_info['registry_sessions'] = registry_sessions
                        new_info = True
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum registry sessions: Access denied'})
                        elif 'STATUS_OBJECT_NAME_NOT_FOUND' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum registry sessions: Non existing pipe'})
                        else:
                            raise e
                    except impacket.smbconnection.SessionError as e:
                        if 'STATUS_OBJECT_NAME_NOT_FOUND' in str(e):
                            Output.error({'target': smbscan.url(), 'message': 'Enum registry sessions: Non existing pipe'})
                        else:
                            raise e

                    if new_info:
                        DB.insert_domain_host(host_info)

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

