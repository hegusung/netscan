import os.path
from urllib.parse import urljoin
from ctypes import *
import socket
import struct
import logging
import re
import traceback

from lib.smbscan.smb import SMBScan
from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds

# source: https://github.com/opsxcq/exploit-CVE-2017-7494

version_pattern = re.compile("^Samba\s+(\d+)\.(\d+)\.(\d+)([^\d].*)?$")

class Module:
    name = 'SambaCry'
    description = 'Check for SambaCry (CVE-2017-7494)'

    def run(self, target, args, creds, timeout):
        vulnerable = check(target['hostname'], target['port'], timeout)

        if vulnerable:
            Output.vuln({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'Vulnerable to CVE-2017-7494 (SambaCry)'})

            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'http',
                'url': 'smb://%s:%d' % (target['hostname'], target['port']),
                'name': 'CVE-2017-7494 (SambaCry)',
                'description': 'Server smb://%s:%d is vulnerable to CVE-2017-7494 (SambaCry)' % (target['hostname'], target['port']),
            }
            DB.insert_vulnerability(vuln_info)

def check(ip, port, timeout):
    vulnerable = False
    try:
        smbscan = SMBScan(ip, port, timeout)
        if smbscan.connect():
            # We are against a SMB server

            smb_info = smbscan.get_server_info()
            os = smb_info['server_os']

            smbscan.disconnect()

            match = version_pattern.match(os)

            if match:
                version = (int(match.group(1)), int(match.group(2)), int(match.group(3)))

                # Afftected software
                # Samba 3.x after 3.5.0 and 4.x before 4.4.14, 4.5.x before 4.5.10, and 4.6.x before 4.6.4

                if version >= (3,5,0) and version < (4,0,0):
                    vulnerable = True

                if version >= (4,0,0) and version < (4,4,14):
                    vulnerable = True

                if version >= (4,5,0) and version < (4,5,10):
                    vulnerable = True

                if version >= (4,6,0) and version < (4,6,4):
                    vulnerable = True

    except Exception as e:
        print('%s: %s\n%s' % (type(e), e, traceback.format_exc()))

    return vulnerable
