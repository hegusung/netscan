import os.path
from time import sleep
import socket
import traceback
import struct
import copy

from lib.smbscan.smb import SMBScan
from .ldap import LDAPScan
from .kerberos import Kerberos

from utils.output import Output
from utils.utils import AuthFailure

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
                    creds_smb['domain'] = 'WORKGROUP'

                if 'password' in creds_smb:
                    try:
                        success, is_admin = smbscan.auth(domain=creds_smb['domain'], username=creds_smb['username'], password=creds_smb['password'])
                        Output.write({'target': smbscan.url(), 'message': 'SMB: Successful authentication with credentials {domain}\\{username} and password {password}'.format(**creds_smb)})
                    except AuthFailure as e:
                        Output.write({'target': smbscan.url(), 'message': 'SMB: Authentication failure with credentials {domain}\\{username} and password {password}: %s'.format(**creds_smb) % str(e)})
                elif 'hash' in creds_smb:
                    try:
                        success, is_admin = smbscan.auth(domain=creds_smb['domain'], username=creds_smb['username'], hash=creds_smb['hash'])
                        Output.write({'target': smbscan.url(), 'message': 'SMB: Successful authentication with credentials {domain}\\{username} and hash {hash}'.format(**creds_smb)})
                    except AuthFailure as e:
                        Output.write({'target': smbscan.url(), 'message': 'SMB: Authentication failure with credentials {domain}\\{username} and hash {hash}: %s'.format(**creds_smb) % str(e)})
                else:
                    try:
                        success, is_admin = smbscan.auth(domain=creds_smb['domain'], username=creds_smb['username'], password='')
                        Output.write({'target': smbscan.url(), 'message': 'SMB: Successful authentication with credentials {domain}\\{username} and no password'.format(**creds_smb)})
                    except AuthFailure as e:
                        Output.write({'target': smbscan.url(), 'message': 'SMB: Authentication failure with credentials {domain}\\{username} and no password: %s'.format(**creds_smb) % str(e)})

                if success:
                    smb_authenticated = True

                    if is_admin:
                        Output.write({'target': smbscan.url(), 'message': 'SMB: Administrative privileges with credentials {domain}\\{username}'.format(**creds_smb)})
        except Exception as e:
            print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))

        # == LDAP check ==
        try:

            ldapscan = LDAPScan(target['hostname'], 389, timeout)
            domain = creds['domain'] if 'domain' in creds else None
            username = creds['username'] if 'username' in creds else None
            password = creds['password'] if 'password' in creds else None
            success, ldap_info = ldapscan.connect(domain, username, password)
            if success:
                ldap_available = True
                ldap_authenticated = True

                Output.write({'target': ldapscan.url(), 'message': 'LDAP: %s  %s' % (ldap_info['dns_hostname'].ljust(30), ldap_info['default_domain_naming_context'])})

                if username == None:
                    Output.write({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with null bind'})
                elif domain != None:
                    Output.write({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with null credentials %s\\%s and password %s' % (domain, username, password)})
                else:
                    Output.write({'target': ldapscan.url(), 'message': 'LDAP: Successful authentication with null credentials %s and password %s' % (username, password)})

            else:
                if username == None:
                    Output.write({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with null bind'})
                elif domain != None:
                    Output.write({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with null credentials %s\\%s and password %s' % (domain, username, password)})
                else:
                    Output.write({'target': ldapscan.url(), 'message': 'LDAP: Failed authentication with null credentials %s and password %s' % (username, password)})
        except Exception as e:
            print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))

        if smb_available or ldap_available:
            # Perform actions

            if 'users' in actions:
                Output.write({'target': ldapscan.url(), 'message': 'Users:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_users():
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s  [%s]' % (user.ljust(30), entry['fullname'].ljust(30), ",".join(entry['tags']))})
                else:
                    raise NotImplementedError('Dumping users through SMB')
            if 'groups' in actions:
                Output.write({'target': ldapscan.url(), 'message': 'Groups:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_groups():
                        group = '%s\\%s' % (entry['domain'], entry['groupname'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   (%d members)   %s' % (group.ljust(40), len(entry['members']), entry['comment'])})
                else:
                    raise NotImplementedError('Dumping groups through SMB')
            if 'hosts' in actions:
                Output.write({'target': ldapscan.url(), 'message': 'Hosts:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_hosts():
                        host = '%s\\%s' % (entry['domain'], entry['hostname'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s   %s' % (host.ljust(40), entry['os'].ljust(20), entry['comment'])})
                else:
                    raise NotImplementedError('Dumping hosts through SMB')
            if 'dns' in actions:
                Output.write({'target': ldapscan.url(), 'message': 'DNS entries:'})
                if ldap_authenticated:
                    for entry in ldapscan.list_dns():
                        Output.write({'target': ldapscan.url(), 'message': '- %s' % (entry,)})
            if 'gpps' in actions:
                Output.write({'target': smbscan.url(), 'message': 'Passwords in GPPs:'})
                if smb_authenticated:
                    for entry in smbscan.list_gpps():
                        Output.write({'target': smbscan.url(), 'message': '- %s   %s' % (entry['username'].ljust(40), entry['password'].ljust(20))})
            if 'spns' in actions:
                Output.write({'target': smbscan.url(), 'message': 'SPNs:'})
                if smb_authenticated:
                    for entry in smbscan.list_spns():
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        tgs_hash = entry['tgs']['tgs'] if 'tgs' in entry['tgs'] else 'Unable to retreive TGS hash'
                        Output.write({'target': smbscan.url(), 'message': '- %s   %s   %s\n%s' % (entry['spn'].ljust(30), user.ljust(40), entry['tgs']['format'], tgs_hash)})
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

                        Output.write({'target': smbscan.url(), 'message': output})
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.write({'target': smbscan.url(), 'message': 'Enum password policy: Access denied'})
                        else:
                            raise e
            if 'users_brute' in actions:
                # Technically only needs kerberos but well....
                if smb_available:
                    try:
                        if not 'domain' in creds or not '.' in creds['domain']:
                            Output.write({'target': smbscan.url(), 'message': 'Users bruteforce: Please provide complete domain fqdn'})
                        else:
                            kerberos = Kerberos(target['hostname'], creds['domain'])
                            Output.write({'target': smbscan.url(), 'message': 'Valid users:'})
                            for valid_user in kerberos.check_users_dump_asreq(actions['users_brute']['username_file']):
                                user = '%s\\%s' % (valid_user['domain'], valid_user['username'])
                                if 'asreq' in valid_user:
                                    Output.write({'target': smbscan.url(), 'message': '- %s  (Kerberos pre-auth disabled !!!)\n%s' % (user.ljust(50), valid_user['asreq'])})
                                else:
                                    Output.write({'target': smbscan.url(), 'message': '- %s' % user})

                    except Exception as e:
                        raise e
            if 'dump_ntds' in actions:
                if smb_authenticated:
                    try:
                        Output.write({'target': smbscan.url(), 'message': 'Dumping NTDS (method: %s):' % actions['dump_ntds']['method']})
                        def ntds_hash(entry):
                            user = '%s\\%s' % (entry['domain'], entry['username'])
                            Output.write({'target': smbscan.url(), 'message': '- %s   %s   (%s)' % (user.ljust(40), entry['hash'].ljust(70), entry['hash_type'])})
                        dumped = smbscan.dump_ntds(actions['dump_ntds']['method'], callback_func=ntds_hash)
                        Output.write({'target': smbscan.url(), 'message': 'Dumped %d hashes' % dumped})
                    except Exception as e:
                        raise e
                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                        if 'access_denied' in str(e):
                            Output.write({'target': smbscan.url(), 'message': 'Enum password policy: Access denied'})
                        else:
                            raise e

        else:
            Output.write({'target': smbscan.url(), 'message': 'LDAP: Unable to connect to both ldap and smb services'})


    except Exception as e:
        Output.write({'target': smbscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        smbscan.disconnect()

