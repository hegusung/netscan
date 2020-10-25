import os.path
from time import sleep
import socket
import traceback
import struct
import copy

from lib.smbscan.smb import SMBScan
from .ldap import LDAPScan

from utils.output import Output

def adscan_worker(target, actions, creds, timeout):
    try:
        smb_available = False
        ldap_available = False

        try:
            smbscan = SMBScan(target['hostname'], 445, timeout)

            # == SMB check ==

            if smbscan.connect():
                # We are against a SMB server

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
                    smb_available = True

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
                Output.write({'target': smbscan.url(), 'message': 'Users:'})
                if ldap_available:
                    for entry in ldapscan.list_users():
                        user = '%s\\%s' % (entry['domain'], entry['username'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s  [%s]' % (user.ljust(30), entry['fullname'].ljust(30), ",".join(entry['tags']))})
                else:
                    raise NotImplementedError('Dumping users through SMB')
            if 'groups' in actions:
                Output.write({'target': smbscan.url(), 'message': 'Groups:'})
                if ldap_available:
                    for entry in ldapscan.list_groups():
                        group = '%s\\%s' % (entry['domain'], entry['groupname'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   (%d members)   %s' % (group.ljust(40), len(entry['members']), entry['comment'])})
                else:
                    raise NotImplementedError('Dumping groups through SMB')
            if 'hosts' in actions:
                Output.write({'target': smbscan.url(), 'message': 'Hosts:'})
                if ldap_available:
                    for entry in ldapscan.list_hosts():
                        host = '%s\\%s' % (entry['domain'], entry['hostname'])
                        Output.write({'target': ldapscan.url(), 'message': '- %s   %s   %s' % (host.ljust(40), entry['os'].ljust(20), entry['comment'])})
                else:
                    raise NotImplementedError('Dumping hosts through SMB')




        else:
            Output.write({'target': smbscan.url(), 'message': 'LDAP: Unable to connect to both ldap and smb services'})


    except Exception as e:
        Output.write({'target': smbscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        smbscan.disconnect()

