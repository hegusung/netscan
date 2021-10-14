import os
from utils.db import DB
from utils.output import Output
from server.smbserver import *
from server.vulnerability_callback import VulnCallback

def run_smb_server(ip, port):
    global vuln_path
    server = SimpleSMBServer(ip,int(port))

    vuln_path = os.path.join(os.path.dirname(__file__), 'empty')

    server.addShare("Files", os.path.join(os.path.dirname(__file__), 'files'), "Files")
    server.addShare("Vuln", vuln_path, "Detect vulns", readOnly='yes')
    server.setSMB2Support(True)

    server.setSMBChallenge('0123456789')

    #server.setLogFile('')

    server.start()

# This part is really quick n' dirty...
def query_file_callback(file_path):
    global vuln_path

    if file_path.startswith(vuln_path):
        vuln_id = file_path.split('/')[-1]
        print("VUlN ID: %s" % vuln_id)

        VulnCallback.check(vuln_id)

def ntlm_challenge(client_ip, ntlm_chall):
    Output.major("NTLM challenge from %s> %s" % (client_ip, ntlm_chall))
    parts = ntlm_chall.split(':')
    DB.insert_domain_user({
        'domain': parts[2],
        'username': parts[0],
        'hash': ntlm_chall,
    })

