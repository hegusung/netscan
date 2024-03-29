#!/usr/bin/env python3

import psutil
import argparse
import threading
from utils.db import DB
from utils.config import Config
from utils.output import Output
from server.http_server import run_http_server
from server.ldap_server import run_ldap_server
from server.smb_server import run_smb_server
from server.vulnerability_callback import VulnCallback

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP Server')
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    Output.setup()

    Config.load_config()
    DB.start_worker(args.nodb)
    DB.save_start()

    VulnCallback.init()

    # Listing interfaces
    Output.success("Listing interface addresses:")
    ifs_addrs = psutil.net_if_addrs()
    for key, value in ifs_addrs.items():
        if str(value[0].family) == 'AddressFamily.AF_INET':
            Output.success(" - %s: %s/%s" % (key.ljust(20), value[0].address, value[0].netmask))

    bind_ip = Config.config.get('Server', 'bind_ip')
    http_port = int(Config.config.get('Server', 'http_port'))
    ldap_port = int(Config.config.get('Server', 'ldap_port'))

    if Config.config.get('Server', 'enable_http') == 'true':
        # Start the HTTP server
        Output.success('Starting HTTP server at http://%s:%d/' % (bind_ip, http_port))
        t_http = threading.Thread(target=run_http_server, args=(bind_ip, http_port))
        t_http.daemon = True
        t_http.start()
    else:
        t_http = None

    if Config.config.get('Server', 'enable_ldap') == 'true':
        # Start the HTTP server
        Output.success('Starting LDAP server at ldap://%s:%d/' % (bind_ip, ldap_port))
        t_ldap = threading.Thread(target=run_ldap_server, args=(bind_ip, ldap_port))
        t_ldap.daemon = True
        t_ldap.start()
    else:
        t_ldap = None


    if Config.config.get('Server', 'enable_smb') == 'true':
        # Start the SMB server
        Output.success('Starting SMB server at smb://%s:%d/' % (bind_ip, 445))
        t_smb = threading.Thread(target=run_smb_server, args=(bind_ip, 445))
        t_smb.daemon = True
        t_smb.start()
    else:
        t_smb = None

    if t_http != None:
        t_http.join()
    if t_smb != None:
        t_smb.join()
    if t_ldap != None:
        t_ldap.join()
