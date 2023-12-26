import os.path
from urllib.parse import urljoin
from ctypes import *
import socket
import struct
import logging
import traceback

import impacket
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5 import transport

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.smbscan.smb import SMBScan

# source: https://github.com/dirkjanm/CVE-2020-1472/blob/master/cve-2020-1472-exploit.py

class Module:
    name = 'ZeroLogon'
    description = 'Check for ZeroLogon (CVE-2020-1472)'

    def run(self, target, target_domain, creds, args, timeout):

        Output.minor({'target': 'smb://%s:%d' % (target['hostname'], 445), 'message': '[%s] Running module...' % self.name})

        vulnerable = check(target['hostname'], 445, timeout)

        if vulnerable:
            Output.vuln({'target': 'smb://%s:%d' % (target['hostname'], 445), 'message': '[%s] Vulnerable to CVE-2020-1472 (ZeroLogon)' % self.name})

            vuln_info = {
                'hostname': target['hostname'],
                'port': 445,
                'service': 'http',
                'url': 'smb://%s:%d' % (target['hostname'], 445),
                'name': 'CVE-2020-1472 (ZeroLogon)',
                'description': 'Server smb://%s:%d is vulnerable to CVE-2020-1472 (ZeroLogon)' % (target['hostname'], 445),
            }
            DB.insert_vulnerability(vuln_info)

def check(ip, port, timeout):
    try:
        smbscan = SMBScan(ip, port, timeout)
        if smbscan.connect():
            # We are against a SMB server

            smb_info = smbscan.get_server_info()
            dc_name = smb_info['hostname']

            return perform_check('\\\\' + dc_name, ip, dc_name)
    except impacket.dcerpc.v5.rpcrt.DCERPCException:
        pass
    except Exception as e:
        Output.error({'target': 'smb://%s:%d' % (ip, 445), 'message': '[ZeroLogon] %s: %s\n%s' % (type(e), e, traceback.format_exc())})

    return False

MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def perform_check(dc_handle, dc_ip, target_computer):
    # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
    rpc_con = None
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
    rpc_con.connect()
    rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
    for attempt in range(0, MAX_ATTEMPTS):
        result = try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer)

        if not result is None:
            break

    if result:
        return True
    else:
        return False

def try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer):
    # Connect to the DC's Netlogon service.


    # Use an all-zero challenge and credential.
    plaintext = b'\x00' * 8
    ciphertext = b'\x00' * 8

    # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
    flags = 0x212fffff

    try:
        # Send challenge and authentication request.
        nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)

        server_auth = nrpc.hNetrServerAuthenticate3(
            rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            target_computer + '\x00', ciphertext, flags
        )


        # It worked!
        assert server_auth['ErrorCode'] == 0
        return True

    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xc0000022:
            return None
        else:
            # Unexpected error code from DC: {ex.get_error_code()}.
            return None
    except BaseException as ex:
        return None
    except ConnectionResetError:
        return None
