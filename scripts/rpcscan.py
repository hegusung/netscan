#!/usr/bin/env python3

import argparse
from utils.utils import normalize_path
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.rpcscan.rpcscan import rpcscan_worker
from utils.db import DB
from utils.config import Config


def main():
    parser = argparse.ArgumentParser(description='RPCScan')
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    parser.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    
    # Actions
    parser.add_argument('--rpc', action='store_true', help='List RPC entries', dest='rpc')
    parser.add_argument('--mounts', action='store_true', help='List NFS mount points', dest='mounts')
    parser.add_argument('--list', action='store_true', help='List content of NFS directories', dest='list')
    parser.add_argument('--uid', metavar='uid', nargs='?', type=int, help='Connect uid (for NFS)', default=0, dest='uid')
    parser.add_argument('--gid', metavar='gid', nargs='?', type=int, help='Connect gid (for NFS)', default=0, dest='gid')
    parser.add_argument('--recurse', metavar='number of times', nargs='?', type=int, help='Number of recursions during directory listing', default=1, dest='recurse')
    
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
    DB.save_start()

    targets = {}
    if args.targets:
        targets['targets'] = args.targets
    if args.target_file:
        targets['target_file'] = normalize_path(args.target_file)

    static_inputs = {}

    actions = {}
    if args.rpc:
        actions['rpc'] = {}
    if args.mounts:
        actions['mounts'] = {}
    if args.list:
        actions['list'] = {'recurse': args.recurse, 'uid': args.uid, 'gid': args.gid}


    rpcscan(targets, static_inputs, args.workers, actions, args.timeout, args.delay, args.resume)

    DB.stop_worker()
    Output.stop()


def rpcscan(input_targets, static_inputs, workers, actions, timeout, delay, resume):
    args = (actions, timeout)
    dispatch_targets(input_targets, static_inputs, rpcscan_worker, args, workers=workers, delay=delay, resume=resume)


if __name__ == '__main__':
    main()
