#!/usr/bin/env python3

import argparse
from utils.utils import normalize_path
from utils.process_inputs import str_ports, port_file
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.mongoscan.mongoscan import mongoscan_worker
from utils.db import DB
from utils.config import Config


def main():
    parser = argparse.ArgumentParser(description='MongoScan')
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='27017', dest='port')
    parser.add_argument('--port-file', metavar='Port-file', nargs='?', type=port_file, help='Specify a port file', default=None, dest='port_file')
    parser.add_argument('-u', metavar='username', type=str, nargs='?', help='Username', default=None, dest='username')
    parser.add_argument('-d', metavar='database', type=str, nargs='?', help='Database', default='', dest='database')
    parser.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    parser.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    
    # Actions
    parser.add_argument("--dbs", action='store_true', help='List databases')
    
    # Bruteforce
    parser.add_argument("--bruteforce", action='store_true', help='Enable bruteforce')
    parser.add_argument('-U', metavar='username file', type=str, nargs='?', help='Username file (format username or username:password)', default=None, dest='username_file')
    parser.add_argument('-P', metavar='password file', type=str, nargs='?', help='Password file', default=None, dest='password_file')
    parser.add_argument('-W', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers for the bruteforce', default=5, dest='bruteforce_workers')
    
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
    if args.port:
        static_inputs['port'] = args.port
    if args.port_file:
        static_inputs['port'] += normalize_path(args.port_file)
    static_inputs['database'] = args.database

    creds = {}
    if args.username:
        creds['username'] = args.username
    if args.password:
        creds['password'] = args.password

    actions = {}
    if args.dbs:
        actions['list_dbs'] = {}
    if args.bruteforce:
        actions['bruteforce'] ={'username_file': normalize_path(args.username_file), 'password_file': normalize_path(args.password_file), 'workers': args.bruteforce_workers}


    mongoscan(targets, static_inputs, args.workers, actions, creds, args.timeout, args.delay, args.resume)

    DB.stop_worker()
    Output.stop()


def mongoscan(input_targets, static_inputs, workers, actions, creds, timeout, delay, resume):
    args = (actions, creds, timeout)
    dispatch_targets(input_targets, static_inputs, mongoscan_worker, args, workers=workers, delay=delay, resume=resume)


if __name__ == '__main__':
    main()
