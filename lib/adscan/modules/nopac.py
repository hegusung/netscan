import os.path
from urllib.parse import urljoin
from ctypes import *
import socket
import struct
import logging
import traceback

import impacket
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.asn1 import AS_REP
from pyasn1.codec.der import decoder, encoder

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.smbscan.smb import SMBScan

SCAN_THRESHOLD = 0.5

# source: https://github.com/ly4k/Pachine/blob/main/pachine.py

class Module:
    name = 'NoPac'
    description = 'Check for NoPac (CVE-2021-42278 / CVE-2021-42287)'

    def run(self, target, creds, args, timeout):
        if not 'username' in creds:
            Output.minor("Please specify a valid account for the NoPac module")
            return

        username = creds['username']
        domain = creds['domain']
        password = creds['password'] if 'password' in creds else ''
        if 'hash' in creds:
            if ':' in creds['hash']:
                lmhash = creds['hash'].split(':')[0]
                nthash = creds['hash'].split(':')[-1]
            else:
                lmhash = 'aad3b435b51404eeaad3b435b51404ee'
                nthash = creds['hash']
        else:
            lmhash = ''
            nthash = ''

        vulnerable = check(target['hostname'], 445, domain, username, password, lmhash, nthash, timeout)

        if vulnerable:
            Output.vuln({'target': 'smb://%s:%d' % (target['hostname'], 445), 'message': 'Vulnerable to NoPac (CVE-2021-42278 / CVE-2021-42287)'})

            vuln_info = {
                'hostname': target['hostname'],
                'port': 445,
                'service': 'http',
                'url': 'smb://%s:%d' % (target['hostname'], 445),
                'name': 'CVE-2021-42278 / CVE-2021-42287 (NoPac)',
                'description': 'Server smb://%s:%d is vulnerable to NoPac (CVE-2021-42278 / CVE-2021-42287)' % (target['hostname'], 445),
            }
            DB.insert_vulnerability(vuln_info)

def check(ip, port, domain, user, password, lmhash, nthash, timeout):
    try:
        # Checking for CVE-2021-42287. This CVE patched together with CVE-2021-42278

        # Request a TGT without a PAC
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, _, _, _ = getKerberosTGT(
            userName,
            password,
            domain,
            lmhash,
            nthash,
            kdcHost=ip,
            requestPAC=False,
        )
        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        no_pac_len = len(decodedTGT["ticket"]["enc-part"]["cipher"])

        # Request a TGT with a PAC
        tgt, _, _, _ = getKerberosTGT(
            userName,
            password,
            domain,
            lmhash,
            nthash,
            kdcHost=ip,
            requestPAC=True,
        )
        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        pac_len = len(decodedTGT["ticket"]["enc-part"]["cipher"])

        # Check if TGT without PAC is smaller than TGT with PAC. If not, the DC included the
        # PAC, which means that the DC is patched for CVE-2021-42287 and therefore most
        # likely also for CVE-2021-42278
        if no_pac_len < pac_len * SCAN_THRESHOLD:
            # Vulnerable
            return True
        else:
            # Not vulnerable
            return False
    except Exception as e:
        Output.error('%s: %s\n%s' % (type(e), e, traceback.format_exc()))

    return False
