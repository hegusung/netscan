import os.path
from urllib.parse import urljoin
from ctypes import *
import socket
import struct
import logging
import calendar
import time
import re

from utils.output import Output
from utils.db import DB

from impacket import version
from impacket.examples.logger import ImpacketFormatter
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import *
from impacket import ntlm
from impacket.ntlm import AV_PAIRS, NTLMSSP_AV_TIME, NTLMSSP_AV_FLAGS, NTOWFv2, NTLMSSP_AV_TARGET_NAME, NTLMSSP_AV_HOSTNAME,USE_NTLMv2, hmac_md5

# source: https://github.com/fox-it/cve-2019-1040-scanner

class Module:
    name = 'DropTheMic'
    description = 'Check for DropTheMic (CVE-2019-1040)'

    def run(self, target, args, creds, timeout):
        domain = creds['domain'] if 'domain' in creds else None
        user = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None
        ntlm_hash = creds['hash'] if 'hash' in creds else ''

        if not user:
            Output.error({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'Module DropTheMic requires valid credentials'})
            return

        vulnerable = check(target['hostname'], target['port'], domain, user, password, ntlm_hash)

        if vulnerable:
            Output.vuln({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'Vulnerable to CVE-2019-1040 (DropTheMic)'})

            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'smb',
                'url': 'smb://%s:%d' % (target['hostname'], target['port']),
                'name': 'CVE-2019-1040 (DropTheMic)',
                'description': 'Server smb://%s:%d is vulnerable to CVE-2019-1040 (DropTheMic)' % (target['hostname'], target['port']),
            }
            DB.insert_vulnerability(vuln_info)

# Slightly modified version of impackets computeResponseNTLMv2
def mod_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                              nthash='', use_ntlmv2=USE_NTLMv2, check=False):

    responseServerVersion = b'\x01'
    hiResponseServerVersion = b'\x01'
    responseKeyNT = NTOWFv2(user, password, domain, nthash)

    av_pairs = AV_PAIRS(serverName)
    av_pairs[NTLMSSP_AV_TARGET_NAME] = 'cifs/'.encode('utf-16le') + av_pairs[NTLMSSP_AV_HOSTNAME][1]
    if av_pairs[NTLMSSP_AV_TIME] is not None:
        aTime = av_pairs[NTLMSSP_AV_TIME][1]
    else:
        aTime = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000))
        av_pairs[NTLMSSP_AV_TIME] = aTime
    av_pairs[NTLMSSP_AV_FLAGS] = b'\x02' + b'\x00' * 3
    serverName = av_pairs.getData()

    temp = responseServerVersion + hiResponseServerVersion + b'\x00' * 6 + aTime + clientChallenge + b'\x00' * 4 + \
           serverName + b'\x00' * 4

    ntProofStr = hmac_md5(responseKeyNT, serverChallenge + temp)

    ntChallengeResponse = ntProofStr + temp
    lmChallengeResponse = hmac_md5(responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
    sessionBaseKey = hmac_md5(responseKeyNT, ntProofStr)

    return ntChallengeResponse, lmChallengeResponse, sessionBaseKey

orig_type1 = ntlm.getNTLMSSPType1
# Wrapper to remove signing flags
def mod_getNTLMSSPType1(workstation='', domain='', signingRequired = False, use_ntlmv2 = USE_NTLMv2):
    return orig_type1(workstation, domain, False, use_ntlmv2)

def check(remote_host, port, domain, username, password, ntlm_hash):
    if ntlm_hash:
        lmhash, nthash = ntlm_hash.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        smbClient = SMBConnection(remote_host, remote_host, sess_port=int(port)) #, preferredDialect=SMB2_DIALECT_21
    except:
        return

    # This isn't really compatible.... with multithreading
    ntlm.computeResponseNTLMv2 = mod_computeResponseNTLMv2
    try:
        smbClient.login(username, password, domain, lmhash, nthash)

        try:
            server_os = str(smbClient._SMBConnection.get_server_lanman())
        except:
            server_os = str(smbClient.getServerOS())

        # Needs to be a windows server
        if not server_os.startswith("Windows "):
            return False

        # smbserver.py and samba false positives
        if server_os in ["Windows 255.255 Build 65535", "Windows 6.1 Build 0"]:
            return False

        return True
    except SessionError as exc:
        if 'STATUS_INVALID_PARAMETER' in str(exc):
            pass
        else:
            Output.error('Unexpected Exception while authenticating to %s: %s' % (remote_host, exc))

        return False

    smbClient.close()
