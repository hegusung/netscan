import os.path
from urllib.parse import urljoin
from ctypes import *
import socket
import struct
import logging

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds

# source: https://github.com/ollypwn/SMBGhost/blob/master/scanner.py

class Module:
    name = 'SMBGhost'
    description = 'Check for SMBGhost (CVE-2020-0796)'

    def run(self, target, args, creds, timeout):
        vulnerable = check(target['hostname'], target['port'], timeout)

        if vulnerable:
            Output.vuln({'target': 'smb://%s:%d' % (target['hostname'], target['port']), 'message': 'Vulnerable to CVE-2020-0796 (SMBGhost)'})

            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'smb',
                'url': 'smb://%s:%d' % (target['hostname'], target['port']),
                'name': 'CVE-2020-0796 (SMBGhost)',
                'description': 'Server smb://%s:%d is vulnerable to CVE-2020-0796 (SMBGhost)' % (target['hostname'], target['port']),
            }
            DB.insert_vulnerability(vuln_info)

def check(ip, port, timeout):
    pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

    sock = socket.socket(socket.AF_INET)
    sock.settimeout(timeout)

    try:
        sock.connect(( str(ip),  port ))

        sock.send(pkt)

        nb, = struct.unpack(">I", sock.recv(4))
        res = sock.recv(nb)

        if res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00":
            vulnerable = False
        else:
            vulnerable = True
    except:
        vulnerable = False
    finally:
        sock.close()

    return vulnerable
