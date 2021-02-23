#!/usr/bin/python3

import argparse
import threading

from utils.db import DB
from utils.config import Config
from utils.output import Output
from server.http_server import run_http_server
from server.smb_server import run_smb_server

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP Server')
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    Config.load_config()
    DB.start_worker(args.nodb)

    Output.setup()

    bind_ip = Config.config.get('Server', 'bind_ip')
    http_port = int(Config.config.get('Server', 'http_port'))

    if Config.config.get('Server', 'enable_http') == 'true':
        # Start the HTTP server
        Output.success('Starting HTTP server at http://%s:%d/' % (bind_ip, http_port))
        t_http = threading.Thread(target=run_http_server, args=(bind_ip, http_port))
        t_http.daemon = True
        t_http.start()
    else:
        t_http = None

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
