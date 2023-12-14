import os.path
import urllib
from urllib.parse import urljoin
from ctypes import *
import struct
import logging
import traceback

import socket
import ssl
import ldap3
import asyncio
from msldap.connection import MSLDAPClientConnection
from msldap.commons.factory import LDAPConnectionFactory

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.smbscan.smb import SMBScan

# source: https://github.com/zyn3rgy/LdapRelayScan/blob/main/LdapRelayScan.py

class Module:
    name = 'LDAP_Security'
    description = 'Check for LDAP signing and channel binding [authenticated - kerberos not supported]'

    def run(self, target, target_domain, creds, args, timeout):
        if not 'username' in creds:
            Output.minor("[%s] Module requires a valid account" % self.name)
            return

        if 'kerberos' in creds:
            Output.minor("[%s] Module requires an user and password/hash authentication" % self.name)
            return
        
        username = creds['domain'] + '\\' + creds['username']
        if 'password' in creds:
            password = creds['password']
        elif 'hash' in creds:
            if ':' in creds['hash']:
                password = creds['hash']
            else:
                lmhash = 'aad3b435b51404eeaad3b435b51404ee'
                password = lmhash + ':' + creds['hash']
        else:
            password = None

        if password == None:
            Output.minor("[%s] Module requires a valid user and password/hash authentication" % self.name)
            return

        ldapIsProtected = run_ldap(username, password, target['hostname'])

        Output.minor({'target': 'ldap://%s' % (target['hostname'],), 'message': "[%s] Running module..." % self.name})

        if ldapIsProtected == False:
            Output.vuln({'target': 'ldap://%s:%d' % (target['hostname'], 389), 'message': '[%s] LDAP signing requirements not enforced' % self.name})

            vuln_info = {
                'hostname': target['hostname'],
                'port': 389,
                'service': 'ldap',
                'url': 'ldap://%s:%d' % (target['hostname'], 389),
                'name': 'LDAP signing requirements not enforced',
                'description': 'LDAP Service ldap://%s:%d does not have the signing requirements enforced' % (target['hostname'], 389),
            }
            DB.insert_vulnerability(vuln_info)

        if DoesLdapsCompleteHandshake(target['hostname']) == True:

            ldapsChannelBindingAlwaysCheck = run_ldaps_noEPA(username, password, target['hostname'])
            ldapsChannelBindingWhenSupportedCheck = asyncio.run(run_ldaps_withEPA(username, password, target['hostname'], creds['domain'], timeout))

            if ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == True:
                Output.vuln({'target': 'ldaps://%s:%d' % (target['hostname'], 636), 'message': '[%s] LDAPS channel binding set to "when supported"' % self.name})

                vuln_info = {
                    'hostname': target['hostname'],
                    'port': 636,
                    'service': 'ldaps',
                    'url': 'ldaps://%s:%d' % (target['hostname'], 636),
                    'name': 'LDAP channel binding set to \"when supported\"',
                    'description': 'LDAP Service ldaps://%s:%d channel binding set to "when supported", relaying may be possible depending on the client\'s support for channel binding' % (target['hostname'], 636),
                }
                DB.insert_vulnerability(vuln_info)

            elif ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == False:
                Output.vuln({'target': 'ldaps://%s:%d' % (target['hostname'], 636), 'message': '[%s] LDAPS channel binding set to "never"' % self.name})

                vuln_info = {
                    'hostname': target['hostname'],
                    'port': 636,
                    'service': 'ldaps',
                    'url': 'ldaps://%s:%d' % (target['hostname'], 636),
                    'name': 'LDAP channel binding set to \"never\"',
                    'description': 'LDAP Service ldaps://%s:%d channel binding set to "never", relaying is possible' % (target['hostname'], 636),
                }
                DB.insert_vulnerability(vuln_info)

            elif ldapsChannelBindingAlwaysCheck == True:
                # Not vulnerable
                pass
            else:
                Output.error({'target': 'ldap://%s:%d' % (target['hostname'], 389), 'message': "[" + self.name + "] ERROR: For troubleshooting:\nldapsChannelBindingAlwaysCheck - " +str(ldapsChannelBindingAlwaysCheck)+"\nldapsChannelBindingWhenSupportedCheck: "+str(ldapsChannelBindingWhenSupportedCheck) })

            
#Conduct and LDAP bind and determine if server signing
#requirements are enforced based on potential errors
#during the bind attempt. 
def run_ldap(inputUser, inputPassword, dcTarget):
    ldapServer = ldap3.Server(dcTarget, use_ssl=False, port=389, get_info=ldap3.ALL)
    ldapConn = ldap3.Connection(ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM)
    if not ldapConn.bind():
        if "stronger" in str(ldapConn.result):
            return True #because LDAP server signing requirements ARE enforced
        elif "data 52e" or "data 532" in str(ldapConn.result):
            raise Exception("Invalid credentials")
        else:
            raise Exception("LDAP_security: UNEXPECTED ERROR: " + str(ldapConn.result))
    else:
        #LDAPS bind successful
        return False #because LDAP server signing requirements are not enforced

#Domain Controllers do not have a certificate setup for
#LDAPS on port 636 by default. If this has not been setup,
#the TLS handshake will hang and you will not be able to
#interact with LDAPS. The condition for the certificate
#existing as it should is either an error regarding
#the fact that the certificate is self-signed, or
#no error at all. Any other "successful" edge cases
#not yet accounted for.
def DoesLdapsCompleteHandshake(dcIp):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(5)
  ssl_sock = ssl.wrap_socket(s,
                            cert_reqs=ssl.CERT_OPTIONAL,
                            suppress_ragged_eofs=False,
                            do_handshake_on_connect=False)
  ssl_sock.connect((dcIp, 636))
  try:
    ssl_sock.do_handshake()
    ssl_sock.close()
    return True
  except Exception as e:
    if "CERTIFICATE_VERIFY_FAILED" in str(e):
        ssl_sock.close()
        return True
    if "handshake operation timed out" in str(e):
        ssl_sock.close()
        return False
    else:
        Output.error({'target': 'ldaps://%s:%d' % (dcIp, 636), 'message': "[LDAP_Security] Unexpected error during LDAPS handshake: " + str(e)})
    ssl_sock.close()

#Conduct a bind to LDAPS and determine if channel
#binding is enforced based on the contents of potential
#errors returned. This can be determined unauthenticated,
#because the error indicating channel binding enforcement
#will be returned regardless of a successful LDAPS bind.
def run_ldaps_noEPA(inputUser, inputPassword, dcTarget):
    try:
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        ldapServer = ldap3.Server(
            dcTarget, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
        ldapConn = ldap3.Connection(
            ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM)
        if not ldapConn.bind():
            if "data 80090346" in str(ldapConn.result):
                return True #channel binding IS enforced
            elif "data 52e" in str(ldapConn.result):
                return False #channel binding not enforced
            else:
                Output.error({'target': 'ldaps://%s:%d' % (dcTarget, 636), 'message': "[LDAP_Security] UNEXPECTED ERROR: " + str(ldapConn.result)})
        else:
            #LDAPS bind successful
            return False #because channel binding is not enforced
    except Exception as e:
        Output.error({'target': 'ldaps://%s:%d' % (dcTarget, 636), 'message': "[LDAP_Security] Ensure DNS is resolving properly, and that you can reach LDAPS on this host"})

#Conduct a bind to LDAPS with channel binding supported
#but intentionally miscalculated. In the case that and
#LDAPS bind has without channel binding supported has occured,
#you can determine whether the policy is set to "never" or
#if it's set to "when supported" based on the potential
#error recieved from the bind attempt.
async def run_ldaps_withEPA(inputUser, inputPassword, dcTarget, fqdn, timeout):
    try:
        quoted_pass = urllib.parse.quote(inputPassword)
        quoted_pass = quoted_pass.replace('/', '%2F')
        url = 'ldaps+ntlm-password://'+inputUser + ':' + quoted_pass +'@' + dcTarget
        conn_url = LDAPConnectionFactory.from_url(url)
        ldaps_client = conn_url.get_client()
        ldaps_client.target.timeout = timeout
        ldaps_client.creds.secret = urllib.parse.unquote(quoted_pass)
        ldapsClientConn = MSLDAPClientConnection(ldaps_client.target, ldaps_client.creds)
        _, err = await ldapsClientConn.connect()
        if err is not None:
            raise err
        #forcing a miscalculation of the "Channel Bindings" av pair in Type 3 NTLM message
        ldapsClientConn.cb_data = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        _, err = await ldapsClientConn.bind()
        if "data 80090346" in str(err):
            return True
        elif "data 52e" in str(err):
            return False
        elif err is not None:
            Output.error({'target': 'ldaps://%s:%d' % (dcTarget, 636), 'message': "[LDAP_Security] ERROR while connecting to " + dcTarget + ": " + err})
        elif err is None:
            return False
    except Exception as e:
        traceback.print_exc()
        Output.error({'target': 'ldaps://%s:%d' % (dcTarget, 636), 'message': "[LDAP_Security] Something went wrong during ldaps_withEPA bind:" + str(e)})
