import os.path
from time import sleep
import socket
import traceback
import struct
import ntpath

import impacket
from impacket.smbconnection import SessionError, SMBConnection
from impacket.nmb import NetBIOSTimeout, NetBIOSError
from impacket.smb import SMB_DIALECT
from impacket.smb3structs import SMB2_DIALECT_21
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.rpcrt import DCERPCException

from utils.output import Output

"""
Lot of code here taken from CME, @byt3bl33d3r did an awesome job with impacket
"""

def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, 'Yi', suffix)

import random
import string
def gen_random_string(length=10):
    return ''.join(random.sample(string.ascii_letters, int(length)))

class AuthFailure(Exception):
    pass

class SMBScan:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.conn = None
        self.authenticated = False
        self.smbv1 = None

    def url(self, path=None):
        if path:
            return "smb://%s:%d%s" % (self.hostname, self.port, path)
        else:
            return "smb://%s:%d" % (self.hostname, self.port)

    def auth(self, domain='WORKGROUP', username=None, password=None, hash=None):
        if not self.conn:
            Output.write({'target': self.url(), 'message': 'enum_host_info(): please connect first'})

        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

        success = False
        is_admin = False

        try:
            if username == None:
                self.conn.login('' , '')
                is_admin = self.check_if_admin(domain, '', '', hash)
            else:
                if password != None:
                    self.conn.login(username, password, domain)
                elif hash != None:
                    if not ':' in hash:
                        nt_hash = hash
                        lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
                    else:
                        nt_hash = hash.split(':')[1]
                        lm_hash = hash.split(':')[0]

                    self.conn.login(username, '', domain, lm_hash, nt_hash)

                is_admin = self.check_if_admin(domain, username, password, hash)

            success = True

        except impacket.smbconnection.SessionError as e:
            error, desc = e.getErrorString()
            raise AuthFailure(error)
        except Exception as e:
            Output.write({'target': self.url(), 'message': "%s:%s\n%s" % (type(e), str(e), traceback.format_exc())})
            pass

        self.authenticated = success

        return success, is_admin

    def get_server_info(self):
        if not self.conn:
            self.conn()
        if not self.authenticated:
            try:
                self.auth()
            except AuthFailure:
                pass

        domain    = self.conn.getServerDNSDomainName()
        hostname  = self.conn.getServerName()
        try:
            server_os = str(self.conn._SMBConnection.get_server_lanman())
        except:
            server_os = str(self.conn.getServerOS())
        signing   = self.conn.isSigningRequired() if self.smbv1 else self.conn._SMBConnection._Connection['RequireSigning']

        if not domain:
            domain = hostname

        smb_info = {}
        if domain:
            smb_info['domain'] = domain
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

    def check_if_admin(self, domain='WORKGROUP', username='', password=None, hash=None):
        admin_privs = False

        stringBinding = r'ncacn_np:{}[\pipe\svcctl]'.format(self.hostname)

        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_dport(self.port)

        lmhash = ''
        nthash = ''
        if hash:
            lmhash, nthash = hash.split(':')
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(username, password if password is not None else '', domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)

        lpMachineName = '{}\x00'.format(self.hostname)
        try:

            # 0xF003F - SC_MANAGER_ALL_ACCESS
            # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx

            resp = scmr.hROpenSCManagerW(dce, lpMachineName, 'ServicesActive\x00', 0xF003F)
            admin_privs = True
        except DCERPCException:
            pass

        return admin_privs

    def list_shares(self):
        temp_dir = ntpath.normpath("\\" + gen_random_string())

        try:
            for share in self.conn.listShares():
                share_name = share['shi1_netname'][:-1]
                share_remark = share['shi1_remark'][:-1]
                share_info = {'name': share_name, 'remark': share_remark, 'access': []}
                read = False
                write = False

                try:
                    self.conn.listPath(share_name, '*')
                    read = True
                    share_info['access'].append('READ')
                except SessionError:
                    pass

                try:
                    self.conn.createDirectory(share_name, temp_dir)
                    self.conn.deleteDirectory(share_name, temp_dir)
                    write = True
                    share_info['access'].append('WRITE')
                except SessionError:
                    pass

                yield share_info

        except Exception as e:
            Output.write({'target': self.url(), 'message': "%s:%s\n%s" % (type(e), str(e), traceback.format_exc())})

    def list_dir(self, share, path):
        contents = self.conn.listPath(share, '*')

    def list_content(self, path="\\", share=None, recurse=3):
        if not share:
            return
        try:
            has_content = False

            try:
                contents = self.conn.listPath(share, path+"\\*")
            except SessionError as e:
                if 'STATUS_ACCESS_DENIED' not in str(e):
                    Output.write({'target': self.url(), 'message': "Failed listing files on share {} in directory {}: {}".format(share, path, e)})
                return

            for content in contents:
                has_content = True

                filename = content.get_longname()
                if path.endswith('\\'):
                    filepath = "%s%s" % (path, filename)
                else:
                    filepath = "%s\\%s" % (path, filename)
                is_readonly = content.is_readonly()
                is_directory = content.is_directory()

                if filename in ['.', '..']:
                    continue

                if not is_directory:
                    size = content.get_filesize()
                    yield {'type': 'file', 'name': filepath, 'size': size}
                else:
                    if not filepath.endswith('\\'):
                        filepath = "%s\\" % filepath

                    if recurse <= 0:
                        yield {'type': 'folder', 'name': filepath}
                    else:
                        for data in self.list_content(path=filepath, share=share, recurse=recurse-1):
                            yield data

            if not has_content and path != '\\':
                yield {'type': 'folder', 'name': path}
        except Exception as e:
            Output.write({'target': self.url(), 'message': "%s:%s\n%s" % (type(e), str(e), traceback.format_exc())})
