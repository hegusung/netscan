import os.path
import logging
from time import sleep
import socket
import ssl
import OpenSSL
import traceback
import struct


"""
Taken from https://github.com/SecureAuthCorp/impacket/blob/master/examples/rdp_check.py
"""

class RDP:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

    def url(self, path=None):
        return "rdp://%s:%d" % (self.hostname, self.port)

    def get_certificate_info(self):
        socket.setdefaulttimeout(self.timeout)
        cert = ssl.get_server_certificate((self.hostname, self.port))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

        server_hostname = x509.get_issuer().CN

        return {'hostname': server_hostname}


    def disconnect(self):
        pass

    """
    def auth(self, domain='WORKGROUP', username=None, password=None, hash=None):
        if not self.conn:
            Output.write({'target': self.url(), 'message': 'enum_host_info(): please connect first'})

        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

        success = False
        is_admin = False

        try:
            if username == None or username == '':
                self.conn.login('' , '')
                self.is_admin = self.check_if_admin(domain, '', '', hash)
                self.creds = {'username': '', 'password': '', 'domain': domain}
            else:
                if password != None:
                    self.conn.login(username, password, domain)
                    self.creds = {'username': username, 'password': password, 'domain': domain}
                elif hash != None:
                    if not ':' in hash:
                        nt_hash = hash
                        lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
                    else:
                        nt_hash = hash.split(':')[1]
                        lm_hash = hash.split(':')[0]

                    self.conn.login(username, '', domain, lm_hash, nt_hash)
                    self.creds = {'username': username, 'hash': hash, 'domain': domain}

                self.is_admin = self.check_if_admin(domain, username, password, hash)

            success = True

        except impacket.smbconnection.SessionError as e:
            error, desc = e.getErrorString()
            if 'STATUS_ACCESS_DENIED' in str(error):
                # Auth success but we have been denied access during check_admin_privs
                success = True
            else:
                raise AuthFailure(error)
        except Exception as e:
            Output.write({'target': self.url(), 'message': "%s:%s\n%s" % (type(e), str(e), traceback.format_exc())})
            pass

        self.authenticated = success

        return success, self.is_admin

    def get_server_info(self):
        if not self.conn:
            self.conn()
        if not self.authenticated:
            try:
                self.auth()
            except AuthFailure:
                pass

        self.domain    = self.conn.getServerDNSDomainName()
        hostname  = self.conn.getServerName()
        try:
            server_os = str(self.conn._SMBConnection.get_server_lanman())
        except:
            server_os = str(self.conn.getServerOS())
        signing   = self.conn.isSigningRequired() if self.smbv1 else self.conn._SMBConnection._Connection['RequireSigning']

        if not self.domain:
            self.domain = hostname

        smb_info = {}
        if self.domain:
            smb_info['domain'] = self.domain
        if hostname:
            smb_info['hostname'] = hostname
        if server_os:
            smb_info['server_os'] = server_os
        if signing:
            smb_info['signing'] = signing

        return smb_info


    def connect(self):
        try:
            self.conn = SMBConnection(self.hostname, self.hostname, None, self.port, timeout=self.timeout, preferredDialect=SMB_DIALECT)
            self.smbv1 = True

            return True
        except (NetBIOSError, socket.error, struct.error, ConnectionResetError, TypeError) as e:
            try:
                self.conn = SMBConnection(self.hostname, self.hostname, None, timeout=self.timeout, preferredDialect=SMB2_DIALECT_21)
                self.smbv1 = False

                return True
            except socket.error as e:
                return False
            except Exception as e:
                return False
        except Exception as e:
            Output.write({'target': self.url(), 'message': "%s:%s\n%s" % (type(e), str(e), traceback.format_exc())})
            return False

    def disconnect(self):
        if self.conn:
            try:
                '''
                    DC's seem to want us to logoff first, windows workstations sometimes reset the connection
                    (go home Windows, you're drunk)
                '''
                self.conn.logoff()
            except:
                pass

            self.smbv1 = None
            self.authenticated = False
            self.conn = None
            self.creds = None
            self.is_admin = False

            self.remote_ops = None
            self.bootkey = None
    """
