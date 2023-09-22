#!/usr/bin/env python3

import argparse
from utils.utils import normalize_path
from utils.process_inputs import str_ports, port_file
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.snmpscan.snmpscan import snmpscan_worker

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='SNMPScan')
    target_group = parser.add_argument_group("Targets")
    target_group.add_argument('targets', type=str, nargs='?')
    target_group.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    target_group.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='161', dest='port')
    target_group.add_argument('--port-file', metavar='Port-file', nargs='?', type=port_file, help='Specify a port file', default=None, dest='port_file')
    
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument('-c', '--community', metavar='community', type=str, nargs='?', help='Community string (SNMPv1/v2)', dest='community')

    query_group = parser.add_argument_group("Query")
    query_group.add_argument('--oid', metavar='OID_String', type=str, nargs='?', help='OID String ("all" to list everything)', dest='oid')

    bruteforce_group = parser.add_argument_group("Bruteforce")
    bruteforce_group.add_argument("--bruteforce", action='store_true', help='Enable bruteforce')
    bruteforce_group.add_argument('-C', metavar='community file', type=str, nargs='?', help='Community list file', default=None, dest='community_file')
    bruteforce_group.add_argument('-W', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers for the bruteforce', default=1, dest='bruteforce_workers')
    
    misc_group = parser.add_argument_group("Misc")
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers', default=10, dest='workers')
    misc_group.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    misc_group.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    # Resume
    parser.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    # DB arguments
    misc_group.add_argument("--nodb", action="store_true", help="Do not add entries to database")

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
    if args.port:
        static_inputs['port'] = args.port
    if args.port_file:
        static_inputs['port'] += normalize_path(args.port_file)

    creds = {}
    if args.community:
        creds['community'] = args.community

    actions = {}
    if args.oid:
        actions['oid'] = args.oid
    if args.bruteforce:
        actions['bruteforce'] = {'community_file': normalize_path(args.community_file), 'workers': args.bruteforce_workers}

    snmpscan(targets, static_inputs, args.workers, actions, creds, args.timeout, args.delay, args.resume)


    DB.stop_worker()
    Output.stop()


def snmpscan(input_targets, static_inputs, workers, actions, creds, timeout, delay, resume):
    args = (actions, creds, timeout)
    dispatch_targets(input_targets, static_inputs, snmpscan_worker, args, workers=workers, delay=delay, resume=resume)


if __name__ == '__main__':
    main()
