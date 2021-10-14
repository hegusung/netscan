import os.path
from time import sleep
import socket
import traceback
import struct
import copy

import dns.resolver
from ldap3.core.exceptions import LDAPSocketSendError

from lib.smbscan.smb import SMBScan
from .ldap import LDAPScan
from .kerberos import Kerberos

from utils.output import Output
from utils.utils import AuthFailure
from utils.db import DB
from utils.modulemanager import ModuleManager

ad_modules = ModuleManager('lib/adscan/modules')

def adscan_worker(target, actions, creds, timeout):
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

                # We need to disconnect after get_server_info
                smbscan.disconnect()

                # Start new connection
                smbscan.connect()

                creds_smb = copy.copy(creds)

                success = False
                is_admin = False

                # Authenticate
                if not 'username' in creds_smb:
                    creds_smb['username'] = ''

                if not 'domain' in creds_smb:
                    raise Exception("Please specify the account domain with -d")

                if 'password' in creds_smb:
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

            domain = creds['domain'] if 'domain' in creds else None
            username = creds['username'] if 'username' in creds else None
            if 'password' in creds:
                password = creds['password']
            elif 'hash' in creds:
                if not ':' in creds['hash']:
                    password = 'aad3b435b51404eeaad3b435b51404ee:%s' % creds['hash']
                else:
                    password = creds['hash']
            else:
                password = None
            try:
                ldapscan = LDAPScan(target['hostname'], 636, timeout, ssl=True)
                success, ldap_info = ldapscan.connect(domain, username, password)
            except LDAPSocketSendError:
                Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Unable to connect to LDAPS, trying to use LDAP'})
                ldapscan = LDAPScan(target['hostname'], 389, timeout)
                success, ldap_info = ldapscan.connect(domain, username, password)

            if success:
                ldap_available = True
                ldap_authenticated = True

                Output.write({'target': ldapscan.url(), 'message': 'LDAP: %s  %s' % (ldap_info['dns_hostname'].ljust(30), ldap_info['default_domain_naming_context'])})
                DB.insert_port({
                    'hostname': target['hostname'],
                    'port': 389,
                    'protocol': 'tcp',
                    'service': 'ldap',
                    'service_info': {
                        'dns_hostname': ldap_info['dns_hostname'],
                        'default_domain_naming_context': ldap_info['default_domain_naming_context'],
                    }
                })

                if username == None:
                    Output.success({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with null bind'})
                elif domain != None:
                    if 'password' in creds:
                        Output.success({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with null credentials %s\\%s and password %s' % (domain, username, password)})

                        cred_info = {
                            'domain': domain,
                            'username': username,
                            'type': 'password',
                            'password': password,
                        }
                        DB.insert_domain_credential(cred_info)

                    elif 'hash' in creds:
                        Output.success({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with null credentials %s\\%s and hash %s' % (domain, username, password)})

                        cred_info = {
                            'domain': domain,
                            'username': username,
                            'type': 'hash',
                            'format': 'ntlm',
                            'hash': password,
                        }
                        DB.insert_domain_credential(cred_info)
                else:
                    if 'password' in creds:
                        Output.success({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with null credentials %s and password %s' % (username, password)})
                    elif 'hash' in creds:
                        Output.success({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with null credentials %s and hash %s' % (username, password)})

            else:
                if username == None:
                    Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with null bind'})
                elif domain != None:
                    if 'password' in creds:
                        Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with null credentials %s\\%s and password %s' % (domain, username, password)})
                    elif 'hash' in creds:
                        Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with null credentials %s\\%s and hash %s' % (domain, username, password)})
                else:
                    if 'password' in creds:
                        Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with null credentials %s and password %s' % (username, password)})
                    elif 'hash' in creds:
                        Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with null credentials %s and hash %s' % (username, password)})
        except Exception as e:
            print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))

        if smb_available or ldap_available:
            # Perform actions

            if 'users' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Users:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_users():
                        DB.insert_domain_user({
                            'domain': entry['domain'],
                            'username': entry['username'],
                            'fullname': entry['fullname'],
                            'comment': entry['comment'],
                            'sid': entry['sid'],
                            'rid': entry['rid'],
                            'dn': entry['dn'],
                            'tags': entry['tags'],
                        })
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s  [%s]' % (user.ljust(30), entry['fullname'].ljust(30), ",".join(entry['tags']))})
                else:
                    raise NotImplementedError('Dumping users through SMB')

            if 'admins' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Admins:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_admins():
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (entry['user'].ljust(30), '; '.join(entry['groups']))})
                else:
                    raise NotImplementedError('Dumping users through SMB')

            if 'rdp' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Users with RDP access:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_rdp_users():
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s  [%s]' % (user.ljust(30), entry['fullname'].ljust(30), ",".join(entry['tags']))})
                else:
                    raise NotImplementedError('Dumping users through SMB')


            if 'groups' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Groups:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_groups():
                        DB.insert_domain_group({
                            'domain': entry['domain'],
                            'groupname': entry['groupname'],
                            'comment': entry['comment'],
                            'sid': entry['sid'],
                            'rid': entry['rid'],
                            'dn': entry['dn'],
                            'members': entry['members'],
                            'tags': entry['tags'],
                        })

                        group = '%s\\%s' % (entry['domain'], entry['groupname'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   (%d members)   %s  [%s]' % (group.ljust(40), len(entry['members']), entry['comment'].ljust(30), ",".join(entry['tags']))})
                else:
                    raise NotImplementedError('Dumping groups through SMB')
            if 'hosts' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Hosts:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_hosts():
                        DB.insert_domain_host({
                            'domain': entry['domain'],
                            'os': entry['os'],
                            'hostname': entry['hostname'],
                            'comment': entry['comment'],
                            'tags': entry['tags'],
                            'sid': entry['sid'],
                        })

                        host = '%s\\%s' % (entry['domain'], entry['hostname'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s   %s  [%s]' % (host.ljust(30), entry['os'].ljust(20), entry['comment'].ljust(25), ','.join(entry['tags']))})
                else:
                    raise NotImplementedError('Dumping hosts through SMB')
            if 'dns' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'DNS entries:'})
                if ldap_authenticated:
                    dns_timeout = False
                    for entry in ldapscan.list_dns():
                        # resolve dns entry

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

            if 'gpps' in actions:
                Output.highlight({'target': smbscan.url(), 'message': 'Passwords in GPPs:'})
                if smb_authenticated:
                    for entry in smbscan.list_gpps():
                        # insert domain vulnerability
                        DB.insert_domain_vulnerability({
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
                    for entry in smbscan.list_spns():
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        tgs_hash = entry['tgs']['tgs'] if 'tgs' in entry['tgs'] else 'Unable to retreive TGS hash'
                        Output.write({'target': smbscan.url(), 'message': '- %s   %s   %s\n%s' % (entry['spn'].ljust(30), user.ljust(40), entry['tgs']['format'], tgs_hash)})

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
                    for entry in ldapscan.list_trusts():
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s   %s   [%s]' % (entry['domain'].ljust(30), entry['direction'].ljust(20), entry['type'].ljust(20), ','.join(entry['tags']))})
                else:
                    raise NotImplementedError('Dumping hosts through LDAP')

            if 'casrv' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'CA server:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_casrv():
                        Output.write({'target': ldapscan.url(), 'message': '- %s %s' % (entry['name'].ljust(30), entry['hostname'])})
                else:
                    raise NotImplementedError('Dumping hosts through LDAP')

            if 'cacerts' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'CA certs:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_cacerts():
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (entry['algo'].ljust(30), ','.join(entry['common_names']))})
                else:
                    raise NotImplementedError('Dumping hosts through LDAP')

            if 'gpos' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'Vulnerable GPOs:'})
                if smb_authenticated and ldap_authenticated:
                    for entry in ldapscan.list_writable_GPOs(smbscan):
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (entry['name'].ljust(40), entry['path'])})

            if 'acl' in actions:
                Output.highlight({'target': ldapscan.url(), 'message': 'ACLs of the current user:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_acls():
                        if len(entry['rights']) > 0:
                            Output.write({'target': ldapscan.url(), 'message': '- (%s) %s ->   %s   [%s]' % (entry['type'], entry['name'].ljust(30), entry['target'].ljust(30), ','.join(entry['rights']))})

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
                                        'domain': valid_user['domain'],
                                        'name': 'Kerberos pre-auth disabled',
                                        'description': 'Kerberos pre-auth is disabled for user %s\%s' % (valid_user['domain'], valid_user['username']),
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
                        for entry in ldapscan.dump_gMSA():
                            user = '%s\\%s' % (entry['domain'], entry['username'])
                            Output.write({'target': ldapscan.url(), 'message': '- %s   %s' % (user.ljust(40), entry['password'])})

                            cred_info = {
                                'domain': entry['domain'],
                                'username': entry['username'],
                                'type': 'password',
                                'password': entry['password'],
                            }
                            DB.insert_domain_credential(cred_info)
                    else:
                        Output.error({'target': ldapscan.url(), 'message': '--gmsa requires to connect to LDAP using SSL, it is probably not available here :('})
            if 'dump_laps' in actions:
                if ldap_authenticated:
                    Output.highlight({'target': smbscan.url(), 'message': 'LAPS entries:'})
                    for entry in ldapscan.dump_LAPS():
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s   %s' % (user.ljust(40), entry['dns'].ljust(40), entry['password'])})

                        cred_info = {
                            'domain': entry['domain'],
                            'username': entry['username'],
                            'type': 'password',
                            'password': entry['password'],
                        }
                        DB.insert_domain_credential(cred_info)
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
                    ad_modules.execute_modules(actions['modules']['modules'], (target, actions['modules']['args'], timeout))

        else:
            Output.write({'target': smbscan.url(), 'message': 'LDAP: Unable to connect to both ldap and smb services'})


    except Exception as e:
        Output.write({'target': smbscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        smbscan.disconnect()

