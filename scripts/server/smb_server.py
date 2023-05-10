import os
from utils.db import DB
from utils.output import Output
from server.smbserver import *
from server.vulnerability_callback import VulnCallback

def run_smb_server(ip, port):
    server = SimpleSMBServer(ip,int(port))
    
    vuln_path = os.path.join(os.path.dirname(__file__), '..', '..', 'server_data', 'empty')

    server.addShare("Files", os.path.join(os.path.dirname(__file__), '..', '..', 'server_data', 'files'), "Files")
    server.addShare("Vuln", vuln_path, "Detect vulns", readOnly='yes')
    server.setSMB2Support(True)

    server.setSMBChallenge('0123456789')

    #server.setLogFile('')

    server.start()

# This part is really quick n' dirty...
def query_file_callback(client_ip, share_name, file_path):
    Output.highlight("%s> Requested ressource: \\%s\\%s" % (client_ip, share_name, file_path))

    if share_name.lower() == "vuln":
        vuln_id = file_path.split('/')[-1]

        VulnCallback.check(vuln_id)
    elif share_name.lower() == "ipc$":
        if file_path == "spoolss":
            # The module printspooler of smbscan has exploited a machine, create a vuln :
            Output.vuln({'target': '[Vuln] smb://%s:%d' % (client_ip, 445), 'message': 'Has PrintSpooler service enabled and exploitable'})

            vuln_info = {
                'hostname': client_ip,
                'port': 445,
                'service': 'smb',
                'url': 'smb://%s:%d' % (client_ip, 445),
                'name': 'Printspooler enabled',
                'description': 'Host %s has the PrintSpooler service enabled and exploitable' % (client_ip,),
            }
            DB.insert_vulnerability(vuln_info)

def ntlm_challenge(client_ip, ntlm_chall):
    Output.major("NTLM challenge from %s> %s" % (client_ip, ntlm_chall))
    parts = ntlm_chall.split(':')
    DB.insert_domain_user({
        'domain': parts[2],
        'username': parts[0],
        'hash': ntlm_chall,
    })

