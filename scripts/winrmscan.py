#!/usr/bin/env python3

import argparse
from utils.utils import normalize_path
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.winrmscan.winrmscan import winrmscan_worker

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='WinRMScan')
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    parser.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    
    # Authentication
    parser.add_argument('-u', metavar='username', type=str, nargs='?', help='Username', default=None, dest='username')
    parser.add_argument('-d', metavar='domain', type=str, nargs='?', help='Domain', default=None, dest='domain')
    parser.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    parser.add_argument('--hash', metavar='ntlm hash', type=str, nargs='?', help='NTLM hash', default=None, dest='hash')
    parser.add_argument('--cmd', metavar='command', type=str, nargs='?', help='Execute a command', default=None, dest='command')

    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers', default=10, dest='workers')
    
    # Resume
    parser.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    Output.setup()
    Config.load_config()
    DB.start_worker(args.nodb)

    targets = {}
    if args.targets:
        targets['targets'] = args.targets
    if args.target_file:
        targets['target_file'] = normalize_path(args.target_file)

    static_inputs = {}

    creds = {}
    if args.domain:
        creds['domain'] = args.domain
    if args.username:
        creds['username'] = args.username
    if args.password:
        creds['password'] = args.password
    if args.hash:
        creds['hash'] = args.hash

    actions = {}
    if args.command:
        actions['command'] ={'command': args.command}


    winrmscan(targets, static_inputs, args.workers, actions, creds, args.timeout, args.delay, args.resume)


    DB.stop_worker()
    Output.stop()


def winrmscan(input_targets, static_inputs, workers, actions, creds, timeout, delay, resume):
    args = (actions, creds, timeout)
    dispatch_targets(input_targets, static_inputs, winrmscan_worker, args, workers=workers, delay=delay, resume=resume)


if __name__ == '__main__':
    main()
