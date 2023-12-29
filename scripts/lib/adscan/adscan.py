import os
import re
import os.path
from time import sleep
import socket
import traceback
import struct
import copy

import OpenSSL

import dns.resolver
from ldap3.core.exceptions import LDAPSocketSendError

from lib.smbscan.smb import SMBScan
from .ldap import LDAPScan
from .kerberos import Kerberos
from .external import call_certipy
from .accesscontrol import get_owner
from .adedit import ADEdit
from .user import User

from utils.output import Output
from utils.utils import check_ip, AuthFailure
from utils.db import DB
from utils.modulemanager import ModuleManager

ad_modules = ModuleManager('lib/adscan/modules')

windows_build = re.compile("Windows \\S+ Build (\\d+)")

def adscan_worker(target, actions, creds, ldap_protocol, python_ldap, timeout):
    # Process creds
    if 'username' in creds and '\\' in creds['username']:
        creds['domain'] = creds['username'].split('\\')[0]
        creds['username'] = creds['username'].split('\\')[1]
    try:
        smb_available = False
        smb_authenticated = False
        ldap_available = False
        ldap_authenticated = False

        try:
            smbscan = SMBScan(target['hostname'], 445, timeout)

            # == SMB check ==

            if smbscan.connect():
                # We are against a SMB server

                smb_available = True

                # Gather info
                smb_info = smbscan.get_server_info()

                # Get build version
                if smbscan.smbv1:
                    # Get build version via SMB2
                    smbv2 = SMBScan(target['hostname'], 445, timeout, use_smbv1=False)
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

                # We need to disconnect after get_server_info
                smbscan.disconnect()

                # Start new connection
                smbscan.connect()

                success = False
                is_admin = False

                if 'kerberos' in creds:
                    if check_ip(target['hostname']):
                        Output.error("When using kerberos, use the hostname instead of the IP. Aborting")
                        Output.minor("The hostname is probably: %s.%s" % (smb_info['hostname'], smb_info['domain']))
                        return


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

                creds_smb = copy.copy(creds)

                # Authenticate
                if not 'username' in creds_smb:
                    creds_smb['username'] = ''

                if not 'domain' in creds_smb:
                    raise Exception("Please specify the account domain with -d")

                if 'kerberos' in creds:
                    try:
                        dc_ip = creds['dc_ip'] if 'dc_ip' in creds else None

                        success, is_admin = smbscan.kerberos_auth(dc_ip=dc_ip)

                        Output.success({'target': smbscan.url(), 'message': 'Successful authentication from kerberos ticket %s (%s\\%s)' % (ticket, creds['domain'], creds['username'])})

 
                    except AuthFailure as e:
                        Output.minor({'target': smbscan.url(), 'message': 'Authentication failure with kerberos ticket %s (%s\\%s)' % (ticket, creds['domain'], creds['username'])})

                elif 'password' in creds_smb:
                    try:
                        success, is_admin = smbscan.auth(domain=creds_smb['domain'], username=creds_smb['username'], password=creds_smb['password'])
                        Output.success({'target': smbscan.url(), 'message': 'SMB: Successful authentication with credentials {domain}\\{username} and password {password}'.format(**creds_smb)})
                    except AuthFailure as e:
                        Output.minor({'target': smbscan.url(), 'message': 'SMB: Authentication failure with credentials {domain}\\{username} and password {password}: %s'.format(**creds_smb) % str(e)})
                elif 'hash' in creds_smb:
                    try:
                        success, is_admin = smbscan.auth(domain=creds_smb['domain'], username=creds_smb['username'], hash=creds_smb['hash'])
                        Output.success({'target': smbscan.url(), 'message': 'SMB: Successful authentication with credentials {domain}\\{username} and hash {hash}'.format(**creds_smb)})
                    except AuthFailure as e:
                        Output.minor({'target': smbscan.url(), 'message': 'SMB: Authentication failure with credentials {domain}\\{username} and hash {hash}: %s'.format(**creds_smb) % str(e)})
                else:
                    try:
                        success, is_admin = smbscan.auth(domain=creds_smb['domain'], username=creds_smb['username'], password='')
                        Output.success({'target': smbscan.url(), 'message': 'SMB: Successful authentication with credentials {domain}\\{username} and no password'.format(**creds_smb)})
                    except AuthFailure as e:
                        Output.minor({'target': smbscan.url(), 'message': 'SMB: Authentication failure with credentials {domain}\\{username} and no password: %s'.format(**creds_smb) % str(e)})

                if success:
                    smb_authenticated = True

                    if 'password' in creds_smb:
                        cred_info = {
                            'domain': creds['domain'],
                            'username': creds['username'],
                            'type': 'password',
                            'password': creds['password'],
                        }
                        DB.insert_domain_credential(cred_info)

                    elif 'hash' in creds_smb:
                        cred_info = {
                            'domain': creds['domain'],
                            'username': creds['username'],
                            'type': 'hash',
                            'format': 'ntlm',
                            'hash': creds['hash'],
                        }
                        DB.insert_domain_credential(cred_info)

                    if is_admin:
                        Output.major({'target': smbscan.url(), 'message': 'SMB: Administrative privileges with credentials {domain}\\{username}'.format(**creds_smb)})
        except Exception as e:
            print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))

        # == LDAP check ==
        try:

            target_domain = actions['target_domain']
            domain = creds['domain'] if 'domain' in creds else None
            username = creds['username'] if 'username' in creds else None
            password = ''
            ntlm = ''
            if 'password' in creds:
                password = creds['password']
            elif 'hash' in creds:
                if not ':' in creds['hash']:
                    ntlm = 'aad3b435b51404eeaad3b435b51404ee:%s' % creds['hash']
                else:
                    ntlm = creds['hash']
            doKerberos = creds['kerberos'] if 'kerberos' in creds else False
            dc_ip = creds['dc_ip'] if 'dc_ip' in creds else None

            success = False
            if ldap_protocol:
                ldap_protocols = [ldap_protocol]
            else:
                ldap_protocols = ['ldaps', 'ldap', 'gc']

            for ldap_protocol in ldap_protocols:
                success = False
                try:
                    ldapscan = LDAPScan(target['hostname'], timeout, protocol=ldap_protocol, python_ldap=python_ldap)
                    success, ldap_info = ldapscan.connect(target_domain, domain, username, password, ntlm, doKerberos, dc_ip)

                    if success:
                        break

                    Output.minor({'target': ldapscan.url(), 'message': 'Failed to authenticate via %s' % ldap_protocol})
                except OpenSSL.SSL.SysCallError as e:
                    pass
            else:
                Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Unable to connect to LDAP'})

            if success:
                ldap_available = True
                ldap_authenticated = True

                Output.write({'target': ldapscan.url(), 'message': 'LDAP: %s  %s' % (ldap_info['default_domain_naming_context'].ljust(50), ldap_info['domain_sid'])})
                DB.insert_port({
                    'hostname': target['hostname'],
                    'port': 389,
                    'protocol': 'tcp',
                    'service': 'ldap',
                    'service_info': {
                        'domain_sid': ldap_info['domain_sid'],
                        'default_domain_naming_context': ldap_info['default_domain_naming_context'],
                    }
                })

                if doKerberos == True:
                        Output.success({'target': ldapscan.url(), 'message': 'Successful authentication from kerberos ticket %s (%s\\%s)' % (ticket, creds['domain'], creds['username'])})

                elif username == None:
                    Output.success({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with null bind'})
                elif domain != None:
                    if 'password' in creds:
                        Output.success({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with credentials %s\\%s and password %s' % (domain, username, password)})

                        cred_info = {
                            'domain': domain,
                            'username': username,
                            'type': 'password',
                            'password': password,
                        }
                        DB.insert_domain_credential(cred_info)

                    elif 'hash' in creds:
                        Output.success({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with credentials %s\\%s and hash %s' % (domain, username, ntlm)})

                        cred_info = {
                            'domain': domain,
                            'username': username,
                            'type': 'hash',
                            'format': 'ntlm',
                            'hash': ntlm,
                        }
                        DB.insert_domain_credential(cred_info)
                else:
                    if 'password' in creds:
                        Output.success({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with credentials %s and password %s' % (username, password)})
                    elif 'hash' in creds:
                        Output.success({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with credentials %s and hash %s' % (username, password)})

            else:
                if username == None:
                    Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with null bind'})
                elif domain != None:
                    if 'password' in creds:
                        Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with credentials %s\\%s and password %s' % (domain, username, password)})
                    elif 'hash' in creds:
                        Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with credentials %s\\%s and hash %s' % (domain, username, password)})
                else:
                    if 'password' in creds:
                        Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with credentials %s and password %s' % (username, password)})
                    elif 'hash' in creds:
                        Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with credentials %s and hash %s' % (username, password)})
        except Exception as e:
            print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))

        if smb_available or ldap_available:
            # Perform actions

            if 'domains' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Domains'})
                if ldap_authenticated:
                    def callback(entry):
                        #print(entry)
                        domain = entry['domain']
                        domain_sid = entry['sid']

                        DB.insert_domain_domain({
                            'domain': entry['domain'],
                            'name': entry['name'],
                            'parameters': entry['parameters'],
                            'sid': entry['sid'],
                            'dn': entry['dn'],
                            'functionallevel': entry['functionallevel'],
                            # For bloodhound
                            'gpo_effect': entry['gpo_effect'],
                            'trusts': entry['trusts'],
                            'links': entry['links'],
                            'aces': entry['aces'],
                            'owner': get_owner(entry['aces']),
                        })
                        Output.write({'target': ldapscan.url(), 'message': '- %s:' % (entry['domain'],)})
                        Output.write({'target': ldapscan.url(), 'message': '   Forest fonctional level: %s' % entry['functionallevel']})
                        if int(entry['functionallevel']) < 2016:
                                DB.insert_domain_vulnerability({
                                    'hostname': ldapscan.hostname,
                                    'domain': entry['domain'],
                                    'name': 'Insecure Forest functional level',
                                    'description': 'Insecure Forest functional level, is %s, should be at least 2016' % (entry['functionallevel'],),
                                })


                        Output.write({'target': ldapscan.url(), 'message': '   Parameters:'})
                        for param_name, param_value in entry['parameters'].items():
                            Output.write({'target': ldapscan.url(), 'message': '    - %s: %s' % (param_name, param_value)})

                            if param_name == 'ms-DS-MachineAccountQuota' and param_value != 0:
                                DB.insert_domain_vulnerability({
                                    'hostname': ldapscan.hostname,
                                    'domain': entry['domain'],
                                    'name': 'Insecure ms-DS-MachineAccountQuota value',
                                    'description': 'Insecure ms-DS-MachineAccountQuota, is %d, should be 0' % (param_value,),
                                })

                        # List containers
                        Output.write({'target': ldapscan.url(), 'message': '   Containers:'})
                        def callback_containers(entry):
                            DB.insert_domain_container({
                                'domain': entry['domain'],
                                'name': entry['name'],
                                'domain_sid': domain_sid,
                                'dn': entry['dn'],
                                'guid': entry['guid'],
                                # For bloodhound
                                'aces': entry['aces'],
                                'owner': get_owner(entry['aces']),
                            })
                            Output.write({'target': ldapscan.url(), 'message': '    - %s' % (entry['name'],)})

                        ldapscan.list_containers(domain, callback_containers)

                        # List OUs
                        Output.write({'target': ldapscan.url(), 'message': '   OUs:'})
                        def callback_ous(entry):
                            DB.insert_domain_ou({
                                'domain': entry['domain'],
                                'name': entry['name'],
                                'domain_sid': domain_sid,
                                'dn': entry['dn'],
                                'guid': entry['guid'],
                                # For bloodhound
                                'gpo_effect': entry['gpo_effect'],
                                'links': entry['links'],
                                'aces': entry['aces'],
                                'owner': get_owner(entry['aces']),
                            })
                            Output.write({'target': ldapscan.url(), 'message': '    - %s' % (entry['name'],)})

                        ldapscan.list_ous(smbscan, domain, domain_sid, callback_ous)


                    ldapscan.list_domains(smbscan, callback)
                else:
                    raise NotImplementedError('Dumping domains through SMB')

            if 'users' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Users:'})
                if ldap_authenticated:
                    def callback(entry):
                        #print(entry)
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        DB.insert_domain_user({
                            'domain': entry['domain'],
                            'username': entry['username'],
                            'user': user,
                            'fullname': entry['fullname'],
                            'comment': entry['comment'],
                            'created_date': entry['created_date'],
                            'last_logon': entry['last_logon'],
                            'last_password_change': entry['last_password_change'],
                            'primary_gid': entry['primary_gid'],
                            'sid': entry['sid'],
                            'rid': entry['rid'],
                            'dn': entry['dn'],
                            'tags': entry['tags'],
                            'group': entry['group'],
                            'aces': entry['aces'],
                            'owner': get_owner(entry['aces']),
                            'spns': entry['spns'],
                            'allowed_to_delegate_to': entry['allowed_to_delegate_to'],
                            'sid_history': entry['sid_history'],
                        })
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s  [%s]' % (user.ljust(30), entry['fullname'].ljust(30), ",".join(entry['tags']))})

                    ldapscan.list_users(callback)
                else:
                    raise NotImplementedError('Dumping users through SMB')

            if 'admins' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Admins:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_admins():
                        user = '%s\\%s' % (entry['details']['domain'], entry['details']['username'])

                        tags = entry['details']['tags']
                        for g in entry['groups']:
                            groupname = g.split('\\')[-1]
                            tags.append("group:%s" % groupname)

                        DB.insert_domain_user({
                            'domain': entry['details']['domain'],
                            'username': entry['details']['username'],
                            'user': user,
                            'fullname': entry['details']['fullname'],
                            'comment': entry['details']['comment'],
                            'created_date': entry['details']['created_date'],
                            'last_logon': entry['details']['last_logon'],
                            'last_password_change': entry['details']['last_password_change'],
                            'primary_gid': entry['details']['primary_gid'],
                            'sid': entry['details']['sid'],
                            'rid': entry['details']['rid'],
                            'dn': entry['details']['dn'],
                            'tags': tags,
                            'group': entry['details']['group'],
                            'aces': entry['details']['aces'],
                            'owner': get_owner(entry['details']['aces']),
                            'spns': entry['details']['spns'],
                            'allowed_to_delegate_to': entry['details']['allowed_to_delegate_to'],
                            'sid_history': entry['details']['sid_history'],
                        })

                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (entry['user'].ljust(30), '; '.join(entry['groups']))})
                else:
                    raise NotImplementedError('Dumping users through SMB')

            if 'rdp' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Users with RDP access:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_rdp_users():
                        user = '%s\\%s' % (entry['details']['domain'], entry['details']['username'])

                        tags = entry['details']['tags']
                        for g in entry['groups']:
                            groupname = g.split('\\')[-1]
                            tags.append("group:%s" % groupname)

                        DB.insert_domain_user({
                            'domain': entry['details']['domain'],
                            'username': entry['details']['username'],
                            'user': user,
                            'fullname': entry['details']['fullname'],
                            'comment': entry['details']['comment'],
                            'created_date': entry['details']['created_date'],
                            'last_logon': entry['details']['last_logon'],
                            'last_password_change': entry['details']['last_password_change'],
                            'primary_gid': entry['details']['primary_gid'],
                            'sid': entry['details']['sid'],
                            'rid': entry['details']['rid'],
                            'dn': entry['details']['dn'],
                            'tags': tags,
                            'group': entry['details']['group'],
                            'aces': entry['details']['aces'],
                            'owner': get_owner(entry['details']['aces']),
                            'spns': entry['details']['spns'],
                            'allowed_to_delegate_to': entry['details']['allowed_to_delegate_to'],
                            'sid_history': entry['details']['sid_history'],
                        })

                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s  [%s]' % (user.ljust(30), entry['details']['fullname'].ljust(30), ",".join(entry['details']['tags']))})
                else:
                    raise NotImplementedError('Dumping users through SMB')


            if 'groups' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Groups:'})
                if ldap_authenticated:
                    def callback(entry):
                        group = '%s\\%s' % (entry['domain'], entry['groupname'])
                        DB.insert_domain_group({
                            'domain': entry['domain'],
                            'groupname': entry['groupname'],
                            'group': group,
                            'comment': entry['comment'],
                            'sid': entry['sid'],
                            'rid': entry['rid'],
                            'dn': entry['dn'],
                            'members': entry['members'],
                            'tags': entry['tags'],
                            'aces': entry['aces'],
                            'owner': get_owner(entry['aces']),
                            'sid_history': entry['sid_history'],
                        })

                        Output.write({'target': ldapscan.url(), 'message': '- %s   (%d members)   %s  [%s]' % (group.ljust(40), len(entry['members']), entry['comment'].ljust(30), ",".join(entry['tags']))})

                    ldapscan.list_groups(callback)
                else:
                    raise NotImplementedError('Dumping groups through SMB')
            if 'hosts' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Hosts:'})
                if ldap_authenticated:
                    def callback(entry):
                        DB.insert_domain_host({
                            'domain': entry['domain'],
                            'os': entry['os'],
                            'hostname': entry['hostname'],
                            'dns': entry['dns'],
                            'comment': entry['comment'],
                            'dn': entry['dn'],
                            'tags': entry['tags'],
                            'sid': entry['sid'],
                            'primary_gid': entry['primary_gid'],
                            'aces': entry['aces'],
                            'owner': get_owner(entry['aces']),
                            'spns': entry['spns'],
                            'allowed_to_delegate_to': entry['allowed_to_delegate_to'],
                            'allowed_to_act_on_behalf_of_other_identity': entry['allowed_to_act_on_behalf_of_other_identity'],
                            'allowed_to_act_on_behalf_of_other_identity_sids': entry['allowed_to_act_on_behalf_of_other_identity_sids'],
                            'created_date': entry['created_date'],
                            'last_logon': entry['last_logon'],
                            'last_password_change': entry['last_password_change'],
                        })

                        host = '%s\\%s' % (entry['domain'], entry['hostname'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s   %s  [%s]' % (host.ljust(30), entry['os'].ljust(20), entry['comment'].ljust(25), ','.join(entry['tags']))})
                    ldapscan.list_hosts(callback)
                else:
                    raise NotImplementedError('Dumping hosts through SMB')
            if 'dns' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'DNS entries:'})
                if ldap_authenticated:
                    global dns_timeout
                    dns_timeout = False
                    def callback(entry):
                        # resolve dns entry
                        global dns_timeout

                        if not dns_timeout:
                            try:
                                resolver = dns.resolver.Resolver()
                                resolver.timeout = 5
                                resolver.lifetime = 5
                                resolver.nameservers = [target['hostname']]
                                answer = resolver.query(entry, "A")
                                ips = [str(r) for r in answer]
                            except dns.resolver.NXDOMAIN:
                                ips = []
                            except dns.resolver.NoAnswer:
                                ips = []
                            except dns.exception.Timeout:
                                ips = []
                                dns_timeout = True
                            except dns.resolver.NoNameservers:
                                ips = []
                                dns_timeout = True
                        else:
                            ips = []

                        Output.write({'target': ldapscan.url(), 'message': '- %s (%s)' % (entry.ljust(50), ','.join(ips))})

                        if len(ips) != 0:
                            for ip in ips:
                                DB.insert_dns({
                                    'source': entry,
                                    'query_type': 'A',
                                    'target': ip,
                                })

                    ldapscan.list_dns(callback)
                else:
                    raise NotImplementedError('Dumping DNS through SMB')

            if 'gpps' in actions:
                Output.highlight({'target': smbscan.url(), 'message': 'Passwords in GPPs:'})
                if smb_authenticated:
                    for entry in smbscan.list_gpps():
                        # insert domain vulnerability
                        DB.insert_domain_vulnerability({
                            'hostname': target['hostname'],
                            'domain': smb_info['domain'],
                            'name': 'Password in GPP',
                            'description': 'Password in GPP file %s: Username => %s, Newname => %s, Password => %s' % (entry['path'], entry['username'], entry['newname'], entry['password']),
                        })

                        Output.write({'target': smbscan.url(), 'message': '- %s => %s :  %s' % (entry['username'].ljust(40), entry['newname'].ljust(40), entry['password'].ljust(20))})

            if 'kerberoasting' in actions:
                Output.highlight({'target': smbscan.url(), 'message': 'Kerberoasting:'})
                if ldap_authenticated:
                    # First, get our TGT
                    if 'kerberos' in creds:
                        raise NotImplementedError("kerberoasting using a Kerberos ticket")
                    elif 'password' in creds_smb:
                        kerberos = Kerberos(target['hostname'], domain, username=username, password=password)
                    elif 'hash' in creds_smb:
                        kerberos = Kerberos(target['hostname'], domain, username=username, ntlm=ntlm)

                    TGT = kerberos.getTGT()
                    if TGT != None:

                        for user_spn in User.list_spns(ldapscan):
                            entry = user_spn.to_json()

                            if entry['username'] == 'krbtgt': 
                                continue

                            user = '%s\\%s' % (entry['domain'], entry['username'])
                            DB.insert_domain_user({
                                'domain': entry['domain'],
                                'username': entry['username'],
                                'user': user,
                                'fullname': entry['fullname'],
                                'comment': entry['comment'],
                                'created_date': entry['created_date'],
                                'last_logon': entry['last_logon'],
                                'last_password_change': entry['last_password_change'],
                                'primary_gid': entry['primary_gid'],
                                'sid': entry['sid'],
                                'rid': entry['rid'],
                                'dn': entry['dn'],
                                'tags': entry['tags'],
                                'group': entry['group'],
                                'aces': entry['aces'],
                                'owner': get_owner(entry['aces']),
                                'spns': entry['spns'],
                                'allowed_to_delegate_to': entry['allowed_to_delegate_to'],
                                'sid_history': entry['sid_history'],
                            })
                            Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (user.ljust(30), ",".join(entry['spns']))})

                            for spn in entry['spns']:
                                TGS = kerberos.getTGS(spn, TGT)

                                username = entry['username'][:-1] if entry['username'].endswith('$') else entry['username']

                                output = kerberos.TGStoHashcat(TGS, username, spn)

                                cred_info = {
                                    'domain': entry['domain'],
                                    'username': entry['username'],
                                    'type': 'hash',
                                    'format': 'krb5tgs',
                                    'hash': output['tgs'],
                                }
                                DB.insert_domain_credential(cred_info)

                                Output.vuln({'target': smbscan.url(), 'message': '- %s  (Kerberoasting)\n%s' % (user.ljust(50), output['tgs'])})
                    else:
                        Output.error({'target': smbscan.url(), 'message': 'Failed to get your TGT'})

                else:
                    raise NotImplementedError('Dumping users through SMB')

            if 'asreproasting' in actions:
                Output.highlight({'target': smbscan.url(), 'message': 'Kerberoasting:'})
                if ldap_authenticated:
                    for user_roast in User.list_donotrequirepreauth(ldapscan):
                        entry = user_roast.to_json()

                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        DB.insert_domain_user({
                            'domain': entry['domain'],
                            'username': entry['username'],
                            'user': user,
                            'fullname': entry['fullname'],
                            'comment': entry['comment'],
                            'created_date': entry['created_date'],
                            'last_logon': entry['last_logon'],
                            'last_password_change': entry['last_password_change'],
                            'primary_gid': entry['primary_gid'],
                            'sid': entry['sid'],
                            'rid': entry['rid'],
                            'dn': entry['dn'],
                            'tags': entry['tags'],
                            'group': entry['group'],
                            'aces': entry['aces'],
                            'owner': get_owner(entry['aces']),
                            'spns': entry['spns'],
                            'allowed_to_delegate_to': entry['allowed_to_delegate_to'],
                            'sid_history': entry['sid_history'],
                        })
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s  [%s]' % (user.ljust(30), entry['fullname'].ljust(30), ",".join(entry['tags']))})

                        kerberos = Kerberos(target['hostname'], smb_info['domain'])
                        try:
                            asrep = kerberos.asrep_roasting(entry['username'])

                            Output.vuln({'target': smbscan.url(), 'message': '- %s  (Kerberos pre-auth disabled !!!)\n%s' % (user.ljust(50), asrep)})

                            # insert domain vulnerability
                            DB.insert_domain_vulnerability({
                                'hostname': target['hostname'],
                                'domain': entry['domain'],
                                'name': 'Kerberos pre-auth disabled',
                                'description': 'Kerberos pre-auth is disabled for user %s\\%s' % (entry['domain'], entry['username']),
                            })

                            cred_info = {
                                'domain': entry['domain'],
                                'username': entry['username'],
                                'type': 'hash',
                                'format': 'krb5asrep',
                                'hash': asrep,
                            }
                            DB.insert_domain_credential(cred_info)


                        except Exception as e:
                            Output.error({'target': ldapscan.url(), 'message': 'Error while ASREP-Roasting: %s' % str(e)})

                else:
                    raise NotImplementedError('Dumping users through SMB')


            if 'passpol' in actions:
                if smb_authenticated:
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

                        # insert domain vulnerability if lock_threshold == 0
                        if password_policy['lock_threshold'] == 0:
                            DB.insert_domain_vulnerability({
                                'hostname': target['hostname'],
                                'domain': password_policy['domain'],
                                'name': 'No account lockout',
                                'description': 'No account lockout for domain %s, accounts can be bruteforced' % (password_policy['domain'],),
                            })

                        Output.highlight({'target': smbscan.url(), 'message': output})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.write({'target': smbscan.url(), 'message': 'Enum password policy: Access denied'})
                        else:
                            raise e

            if 'trusts' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Trusts:'})
                if ldap_authenticated:
                    def callback(entry):
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s   %s   [%s]' % (entry['domain'].ljust(30), entry['direction'].ljust(20), entry['type'].ljust(20), ','.join(entry['tags']))})
                    ldapscan.list_trusts(callback)
                else:
                    raise NotImplementedError('Dumping trusts through SMB')

            if 'gpos' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'GPOs:'})
                if ldap_authenticated:
                    def callback(entry):
                        #print(entry)
                        DB.insert_domain_gpo({
                            'domain': entry['domain'],
                            'domain_sid': entry['domain_sid'],
                            'name': entry['name'],
                            'guid': entry['guid'],
                            'dn': entry['dn'],
                            'gpcpath': entry['gpcpath'],
                            'aces': entry['aces'],
                            'owner': get_owner(entry['aces']),
                        })
                        Output.write({'target': ldapscan.url(), 'message': '- %s   [%s]' % (entry['name'].ljust(30), entry['gpcpath'])})

                    ldapscan.list_gpos(callback)
                else:
                    raise NotImplementedError('Dumping GPOs through SMB')


            if 'casrv' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'ADCS servers:'})
                if ldap_authenticated:
                    def callback(entry):
                        Output.write({'target': ldapscan.url(), 'message': '- %s %s' % (entry['name'].ljust(30), entry['hostname'])})
                    ldapscan.list_casrv(callback)
                else:
                    raise NotImplementedError('Dumping CA servers through SMB')

            if 'ca_certs' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'CA certs:'})
                if ldap_authenticated:
                    def callback(entry):
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (entry['algo'].ljust(30), ','.join(entry['common_names']))})
                    ldapscan.list_cacerts(callback)
                else:
                    raise NotImplementedError('Dumping CA Cert through SMB')

            if 'certipy' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Certipy:'})
                if ldap_authenticated:
                    ca_vulns, template_vulns = call_certipy(target['hostname'], creds, ldapscan.protocol)

                    Output.highlight({'target': ldapscan.url(), 'message': 'Certificate Authorities vulnerabilities:'})
                    for vuln in ca_vulns:
                        Output.vuln({'target': ldapscan.url(), 'message': '%s (%s) %s' % (('[%s]' % vuln['ca']).ljust(20), vuln['vuln_name'], vuln['description'])})

                        DB.insert_domain_vulnerability({
                            'hostname': target['hostname'],
                            'domain': smb_info['domain'],
                            'name': vuln['vuln_name'],
                            'description': vuln['description'],
                        })

                    Output.highlight({'target': ldapscan.url(), 'message': 'Certificate Templates vulnerabilities:'})
                    for vuln in template_vulns:
                        Output.vuln({'target': ldapscan.url(), 'message': '%s (%s) %s' % (('[%s]' % vuln['template']).ljust(20), vuln['vuln_name'], vuln['description'])})

                        DB.insert_domain_vulnerability({
                            'hostname': target['hostname'],
                            'domain': smb_info['domain'],
                            'name': vuln['vuln_name'],
                            'description': vuln['description'],
                        })

            if 'cert_templates' in actions:
                if ldap_authenticated:
                    enrollment_services = []
                    def callback(entry):
                        enrollment_services.append(entry)
                        Output.write({'target': ldapscan.url(), 'message': "- %s   %s" % (entry['name'].ljust(30), entry['dns'])})

                    Output.highlight({'target': ldapscan.url(), 'message': 'Enrollment Services:'})
                    ldapscan.list_enrollment_services(callback)

                    def callback(entry):
                        enabled = False
                        enrollment_service = None
                        for e_s in enrollment_services:
                            if entry['name'] in e_s['templates']:
                                enabled = True
                                enrollment_service = e_s['name']
                                break

                        if enabled: 
                            Output.write({'target': ldapscan.url(), 'message': "- %s   (Enabled)  => %s" % (entry['name'].ljust(30), enrollment_service)})
                        else:
                            Output.minor({'target': ldapscan.url(), 'message': "- %s   (Disabled)" % (entry['name'].ljust(30),)})


                    Output.highlight({'target': ldapscan.url(), 'message': 'Certificate templates:'})
                    ldapscan.list_cert_templates(callback)
                else:
                    raise NotImplementedError('Dumping hosts through LDAP')

            if 'vuln_gpos' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Vulnerable GPOs:'})
                if smb_authenticated and ldap_authenticated:
                    def callback(entry):
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (entry['name'].ljust(40), entry['path'])})
                    ldapscan.list_writable_GPOs(smbscan, callback)

            if 'acls' in actions:

                if len(actions['acls']['user']) == 0:
                    #domain = creds['domain']
                    username = creds['username']
                elif not '\\' in actions['acls']['user']:
                    #domain = creds['domain']
                    username = actions['acls']['user']
                else:
                    #domain = actions['acls']['user'].split('\\')[0]
                    username = actions['acls']['user'].split('\\')[-1]

                if 'all' in actions['acls']:
                    all = True
                else:
                    all = False

                Output.highlight({'target': ldapscan.url(), 'message': 'ACLs of the user %s:' % username})
                if ldap_authenticated:
                    def callback(entry):
                        if len(entry['rights']) > 0:
                            if 'parameter' in entry:
                                parameter = entry['parameter'] if 'parameter' in entry else entry['guid']
                                Output.write({'target': ldapscan.url(), 'message': '- (%s) %s ->   %s   [%s] %s:%s' % (entry['type'], entry['name'].ljust(30), entry['target'].ljust(30), ','.join(entry['rights']), parameter['type'], parameter['name'])})
                            elif 'guid' in entry:
                                Output.write({'target': ldapscan.url(), 'message': '- (%s) %s ->   %s   [%s] guid:%s' % (entry['type'], entry['name'].ljust(30), entry['target'].ljust(30), ','.join(entry['rights']), entry['guid'])})
                            else:
                                Output.write({'target': ldapscan.url(), 'message': '- (%s) %s ->   %s   [%s]' % (entry['type'], entry['name'].ljust(30), entry['target'].ljust(30), ','.join(entry['rights']))})


                    ldapscan.list_acls(username, callback, all=all)

            if 'constrained_delegation' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Constrained delegation (S4U2Proxy):'})
                if ldap_authenticated:
                    def callback(entry):
                        account = '%s\\%s' % (entry['domain'], entry['name'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s  -> %s' % (account.ljust(40), entry['spn'])})
                    ldapscan.list_constrained_delegations(callback)

            if 'list_groups' in actions:

                if len(actions['list_groups']['user']) == 0:
                    username = creds['username']
                elif not '\\' in actions['list_groups']['user']:
                    username = actions['list_groups']['user']
                else:
                    username = actions['list_groups']['user'].split('\\')[-1]

                for user in username.split(','):
                    Output.highlight({'target': ldapscan.url(), 'message': 'Account %s groups:' % user})
                    if ldap_authenticated:
                        def callback(entry):
                            group = '%s\\%s' % (entry['domain'], entry['groupname'])
                            DB.insert_domain_group({
                                'domain': entry['domain'],
                                'groupname': entry['groupname'],
                                'group': group,
                                'comment': entry['comment'],
                                'sid': entry['sid'],
                                'rid': entry['rid'],
                                'dn': entry['dn'],
                                'members': entry['members'],
                                'tags': entry['tags'],
                                'aces': entry['aces'],
                                'owner': get_owner(entry['aces']),
                                'sid_history': entry['sid_history'],
                            })

                            Output.write({'target': ldapscan.url(), 'message': '- %s   (%d members)   %s  [%s]' % (group.ljust(40), len(entry['members']), entry['comment'].ljust(30), ",".join(entry['tags']))})

                        ldapscan.list_user_groups(user, callback)

            if 'list_users' in actions:

                if len(actions['list_users']['group']) == 0:
                    Output.error({'target': ldapscan.url(), 'message': "--list-users requires a group name"})
                else:
                    if not '\\' in actions['list_users']['group']:
                        #domain = creds['domain']
                        groupname = actions['list_users']['group']
                    else:
                        #domain = actions['list_users']['group'].split('\\')[0]
                        groupname = actions['list_users']['group'].split('\\')[-1]

                    Output.highlight({'target': ldapscan.url(), 'message': 'Group %s users:' % groupname})
                    if ldap_authenticated:
                        def callback(entry):
                            user = '%s\\%s' % (entry['domain'], entry['username'])
                            DB.insert_domain_user({
                                'domain': entry['domain'],
                                'username': entry['username'],
                                'user': user,
                                'fullname': entry['fullname'],
                                'comment': entry['comment'],
                                'created_date': entry['created_date'],
                                'last_logon': entry['last_logon'],
                                'last_password_change': entry['last_password_change'],
                                'primary_gid': entry['primary_gid'],
                                'sid': entry['sid'],
                                'rid': entry['rid'],
                                'dn': entry['dn'],
                                'tags': entry['tags'],
                                'group': entry['group'],
                                'aces': entry['aces'],
                                'owner': get_owner(entry['aces']),
                                'spns': entry['spns'],
                                'allowed_to_delegate_to': entry['allowed_to_delegate_to'],
                                'sid_history': entry['sid_history'],
                            })
                            Output.write({'target': ldapscan.url(), 'message': '- %s   %s  [%s]' % (user.ljust(30), entry['fullname'].ljust(30), ",".join(entry['tags']))})

                        ldapscan.list_group_users(groupname, callback)

            if 'object_acl' in actions:

                if 'all' in actions['object_acl']:
                    all = True
                else:
                    all = False

                Output.highlight({'target': ldapscan.url(), 'message': 'ACL of the object %s:' % actions['object_acl']['object']})
                if ldap_authenticated:
                    def callback(entry):
                        if len(entry['rights']) > 0:
                            if 'parameter' in entry:
                                parameter = entry['parameter'] if 'parameter' in entry else entry['guid']
                                Output.write({'target': ldapscan.url(), 'message': '- (%s) %s ->   %s   [%s] %s' % (entry['type'], entry['name'].ljust(30), entry['target'].ljust(30), ','.join(entry['rights']), parameter)})
                            elif 'guid' in entry:
                                Output.write({'target': ldapscan.url(), 'message': '- (%s) %s ->   %s   [%s] guid:%s' % (entry['type'], entry['name'].ljust(30), entry['target'].ljust(30), ','.join(entry['rights']), entry['guid'])})
                            else:
                                Output.write({'target': ldapscan.url(), 'message': '- (%s) %s ->   %s   [%s]' % (entry['type'], entry['name'].ljust(30), entry['target'].ljust(30), ','.join(entry['rights']))})


                    ldapscan.list_object_acl(actions['object_acl']['object'], callback, all=all)

            if 'gettgt' in actions:
                Output.highlight({'target': smbscan.url(), 'message': 'Dumping the TGT of the current user...'})
                
                if 'kerberos' in creds:
                    output.error({'target': smbscan.url(), 'message': 'You are already specifying a ticket'})
                else:
                    if 'password' in creds_smb:
                        kerberos = Kerberos(target['hostname'], domain, username=username, password=password)
                    elif 'hash' in creds_smb:
                        kerberos = Kerberos(target['hostname'], domain, username=username, ntlm=ntlm)

                    # First, get our TGT
                    TGT = kerberos.getTGT()

                    if TGT != None:
                        # Then, save to file
                        ticket_file = "%s_%s.ccache" % (domain, username)
                        Output.highlight({'target': smbscan.url(), 'message': "Saving TGT to %s" % ticket_file})
                        kerberos.saveTGT(TGT, ticket_file)

            if 'gettgs' in actions:
                spn = actions['gettgs']['spn']
                if 'impersonate' in actions['gettgs']:
                    impersonate = actions['gettgs']['impersonate']
                else:
                    impersonate = None
             
                if 'kerberos' in creds:
                    raise NotImplementedError("--gettgs with a kerberos tgt")

                    TGT = TODO
                else:
                    if 'password' in creds_smb:
                        kerberos = Kerberos(target['hostname'], domain, username=username, password=password)
                    elif 'hash' in creds_smb:
                        kerberos = Kerberos(target['hostname'], domain, username=username, ntlm=ntlm)

                    # First, get our TGT
                    TGT = kerberos.getTGT()

                if TGT != None:
                    if impersonate is None:
                       TGS =  kerberos.getTGS(spn, TGT)
                       ticket_username = username
                    else:
                        # impersonating is a bit more complicated
                       TGS =  kerberos.do_S4U(spn, TGT, impersonate)
                       ticket_username = impersonate

                    # Then, save to file
                    ticket_file = "%s_%s.ccache" % (spn.replace('/', '_'), ticket_username)
                    Output.highlight({'target': smbscan.url(), 'message': "Saving TGS to %s" % ticket_file})
                    kerberos.saveTGS(TGS, ticket_file)


                #Output.highlight({'target': smbscan.url(), 'message': 'Dumping the TGS of the SPN %s...' % spn})
                #smbscan.gettgs(spn, impersonate)

            if 'users_brute' in actions:
                # Technically only needs kerberos but well....
                if smb_available:
                    try:
                        if not 'domain' in creds or not '.' in creds['domain']:
                            Output.highlight({'target': smbscan.url(), 'message': 'Users bruteforce: Please provide complete domain fqdn'})
                        else:
                            kerberos = Kerberos(target['hostname'], creds['domain'])
                            Output.highlight({'target': smbscan.url(), 'message': 'Valid users:'})

                            # if no file is specified, dump a list of users through ldap
                            gen = kerberos.check_users_dump_asreq(ldapscan, username_file=actions['users_brute']['username_file'])
                            for valid_user in gen:
                                user = '%s\\%s' % (valid_user['domain'], valid_user['username'])
                                if 'asreq' in valid_user:
                                    Output.vuln({'target': smbscan.url(), 'message': '- %s  (Kerberos pre-auth disabled !!!)\n%s' % (user.ljust(50), valid_user['asreq'])})

                                    # insert domain vulnerability
                                    DB.insert_domain_vulnerability({
                                        'hostname': target['hostname'],
                                        'domain': valid_user['domain'],
                                        'name': 'Kerberos pre-auth disabled',
                                        'description': 'Kerberos pre-auth is disabled for user %s\\%s' % (valid_user['domain'], valid_user['username']),
                                    })

                                    cred_info = {
                                        'domain': valid_user['domain'],
                                        'username': valid_user['username'],
                                        'type': 'hash',
                                        'format': 'krb5asrep',
                                        'hash': valid_user['asreq'],
                                    }
                                    DB.insert_domain_credential(cred_info)


                                else:
                                    Output.write({'target': smbscan.url(), 'message': '- %s' % user})

                                    DB.insert_domain_user({
                                        'domain': valid_user['domain'],
                                        'username': valid_user['username'],
                                    })


                    except Exception as e:
                        raise e
            if 'dump_gmsa' in actions:
                if ldap_authenticated:
                    if ldapscan.ssl:
                        Output.highlight({'target': smbscan.url(), 'message': 'gMSA entries:'})
                        def callback(entry):
                            user = '%s\\%s' % (entry['domain'], entry['username'])
                            Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (user.ljust(40), entry['password'])})

                            cred_info = {
                                'domain': entry['domain'],
                                'username': entry['username'],
                                'type': 'password',
                                'password': entry['password'],
                            }
                            DB.insert_domain_credential(cred_info)
                        ldapscan.dump_gMSA(callback)
                    else:
                        Output.error({'target': ldapscan.url(), 'message': '--gmsa requires to connect to LDAP using SSL, it is probably not available here :('})
            if 'dump_smsa' in actions:
                if ldap_authenticated:
                    if ldapscan.ssl:
                        Output.highlight({'target': smbscan.url(), 'message': 'sMSA entries:'})
                        def callback(entry):
                            user = '%s\\%s' % (entry['domain'], entry['username'])
                            Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (user.ljust(40), entry['target_host'])})

                        ldapscan.dump_sMSA(callback)
                    else:
                        Output.error({'target': ldapscan.url(), 'message': '--smsa requires to connect to LDAP using SSL, it is probably not available here :('})

            if 'dump_laps' in actions:
                if ldap_authenticated:
                    Output.highlight({'target': smbscan.url(), 'message': 'LAPS entries:'})
                    def callback(entry):
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        if 'password' in entry:
                            Output.write({'target': ldapscan.url(), 'message': '- %s   %s   %s' % (user.ljust(40), entry['dns'].ljust(40), entry['password'])})

                            cred_info = {
                                'domain': entry['domain'],
                                'username': entry['username'],
                                'type': 'password',
                                'password': entry['password'],
                            }
                            DB.insert_domain_credential(cred_info)
                        else:
                            Output.write({'target': ldapscan.url(), 'message': '- %s   %s   Unable to retreive password, unsufficient rights' % (user.ljust(40), entry['dns'].ljust(40))})
                    ldapscan.dump_LAPS(callback)
            if 'dump_ntds' in actions:
                if smb_authenticated:
                    try:
                        Output.highlight({'target': smbscan.url(), 'message': 'Dumping NTDS (method: %s):' % actions['dump_ntds']['method']})
                        def ntds_hash(entry):
                            user = '%s\\%s' % (entry['domain'], entry['username'])
                            Output.write({'target': smbscan.url(), 'message': '- %s   %s   (%s)' % (user.ljust(40), entry['hash'].ljust(70), entry['hash_type'])})

                            cred_info = {
                                'domain': entry['domain'],
                                'username': entry['username'],
                                'type': 'hash',
                                'format': entry['hash_type'],
                                'hash': entry['hash'],
                            }
                            DB.insert_domain_credential(cred_info)

                        dumped = smbscan.dump_ntds(actions['dump_ntds']['method'], callback_func=ntds_hash)
                        Output.write({'target': smbscan.url(), 'message': 'Dumped %d hashes' % dumped})
                    except Exception as e:
                        raise e
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.write({'target': smbscan.url(), 'message': 'Enum password policy: Access denied'})
                        else:
                            raise e

            if 'modules' in actions:
                if smb_available:
                    ad_modules.execute_modules(actions['modules']['modules'], (target, actions['target_domain'], creds, actions['modules']['args'], timeout))

            if 'group_add' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        res = adedit.add_user_to_group(actions['group_add']['group'], actions['group_add']['user'])
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully added user "%s" to group "%s"' % (actions['group_add']['user'], actions['group_add']['group'])})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to add user "%s" to group "%s": %s' % (actions['group_add']['user'], actions['group_add']['group'], res)})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})

            if 'group_del' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        res = adedit.remove_user_from_group(actions['group_del']['group'], actions['group_del']['user'])
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully removed user "%s" from group "%s"' % (actions['group_del']['user'], actions['group_del']['group'])})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to remove user "%s" from group "%s": %s' % (actions['group_del']['user'], actions['group_del']['group'], res)})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})

            if 'set_owner' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        Output.highlight({'target': ldapscan.url(), 'message': 'Backuping the current target ACL: %s...' % (actions['set_owner']['target'],)})
                        res, backup_name, security_descriptor = adedit.backup_acl(actions['set_owner']['target'],)
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully backupped the ACL to the file %s' % (backup_name,)})

                            Output.highlight({'target': ldapscan.url(), 'message': 'Setting "%s" as the object "%s" owner' % (actions['set_owner']['principal'], actions['set_owner']['target'],)})

                            res = adedit.set_owner(actions['set_owner']['principal'], actions['set_owner']['target'], security_descriptor)
                            if res == True:
                                Output.success({'target': ldapscan.url(), 'message': 'Successfully changed the object %s owner' % (actions['set_owner']['target'],)})
                            else:
                                Output.error({'target': ldapscan.url(), 'message': 'Failed to change the owner: %s' % res})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to backup the acl: %s' % res})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})


            if 'add_ace' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        Output.highlight({'target': ldapscan.url(), 'message': 'Backuping the current target ACL: %s...' % (actions['add_ace']['target'],)})
                        res, backup_name, security_descriptor = adedit.backup_acl(actions['add_ace']['target'],)
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully backupped the ACL to the file %s' % (backup_name,)})

                            Output.highlight({'target': ldapscan.url(), 'message': 'Adding the privilege %s for %s to the principal %s' % (actions['add_ace']['right'], actions['add_ace']['principal'], actions['add_ace']['target'],)})

                            res = adedit.add_ace(actions['add_ace']['principal'], actions['add_ace']['right'], actions['add_ace']['target'], security_descriptor)
                            if res == True:
                                Output.success({'target': ldapscan.url(), 'message': 'Successfully added a new ACE to the target %s' % (actions['add_ace']['target'],)})
                            else:
                                Output.error({'target': ldapscan.url(), 'message': 'Failed to add a new ace: %s' % res})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to backup the acl: %s' % res})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})

            if 'restore_acl' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        res = adedit.restore_acl(actions['restore_acl']['file'])
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully restored the ACL'})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to restore the ACL: %s' % res})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})

            if 'add_computer' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        res, computer_dn = adedit.add_computer(actions['add_computer']['computer_name'], actions['add_computer']['computer_password'])
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully added a new computer %s to the domain with the password "%s"' % (computer_dn, actions['add_computer']['computer_password'])})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to add a computer to the domain: %s' % res})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})

            if 'del_object' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        res = adedit.del_object(actions['del_object']['object_dn'])
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully deleted the object %s' % actions['del_object']['object_dn']})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to delete the object: %s' % res})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})

            if 'set_password' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        res = adedit.set_password(actions['set_password']['object_dn'], actions['set_password']['password'])
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully changed the password from the object %s to %s' % (actions['set_password']['object_dn'], actions['set_password']['password'])})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to change the object password: %s' % res})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})

            if 'add_parameter' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        res = adedit.modify_add(actions['add_parameter']['object_dn'], actions['add_parameter']['parameter'], actions['add_parameter']['value'])
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully added "%s" to the parameter %s of the object %s' % (actions['add_parameter']['value'], actions['add_parameter']['parameter'], actions['add_parameter']['object_dn'])})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to add the value: %s' % res})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})

            if 'replace_parameter' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        res = adedit.modify_replace(actions['replace_parameter']['object_dn'], actions['replace_parameter']['parameter'], actions['replace_parameter']['value'])
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully replaced the parameter %s of the object %s with the value "%s"' % (actions['replace_parameter']['parameter'], actions['replace_parameter']['object_dn'], actions['replace_parameter']['value'])})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to replace the value: %s' % res})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})

            if 'delete_parameter' in actions:
                if ldap_authenticated:
                    adedit = ADEdit(ldapscan)

                    if adedit.connect():
                        res = adedit.modify_delete(actions['delete_parameter']['object_dn'], actions['delete_parameter']['parameter'], actions['delete_parameter']['value'])
                        if res == True:
                            Output.success({'target': ldapscan.url(), 'message': 'Successfully deleted the value "%s" from the parameter %s of the object %s' % (actions['delete_parameter']['value'], actions['delete_parameter']['parameter'], actions['delete_parameter']['object_dn'])})
                        else:
                            Output.error({'target': ldapscan.url(), 'message': 'Failed to delete the value: %s' % res})
                    else:
                        Output.error({'target': ldapscan.url(), 'message': 'Error while connecting to LDAP using python-ldap3'})












        else:
            Output.write({'target': smbscan.url(), 'message': 'LDAP: Unable to connect to both ldap and smb services'})


    except Exception as e:
        Output.write({'target': smbscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        smbscan.disconnect()

