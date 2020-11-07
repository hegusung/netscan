#!/usr/bin/python3
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.mysqlscan.mysqlscan import mysqlscan_worker

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='MySQLScan')
    parser.add_argument('targets', type=str)
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='3306', dest='port')
    parser.add_argument('-u', metavar='username', type=str, nargs='?', help='Username', default=None, dest='username')
    parser.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Actions
    parser.add_argument("--dbs", action='store_true', help='List databases')
    parser.add_argument("--hashes", action='store_true', help='Dump database hashes')
    parser.add_argument('--sql', metavar='query', type=str, nargs='?', help='Perform a SQL query', default=None, dest='sql')
    # Bruteforce
    parser.add_argument("--bruteforce", action='store_true', help='Enable bruteforce')
    parser.add_argument('-U', metavar='username file', type=str, nargs='?', help='Username file (format username or username:password)', default=None, dest='username_file')
    parser.add_argument('-P', metavar='password file', type=str, nargs='?', help='Password file', default=None, dest='password_file')
    parser.add_argument('-W', metavar='number worker', nargs='?', type=int, help='Number of concurent workers for the bruteforce', default=5, dest='bruteforce_workers')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    Config.load_config()
    DB.start_worker(args.nodb)

    static_inputs = {}
    if args.port:
        static_inputs['port'] = args.port

    creds = {}
    if args.username:
        creds['username'] = args.username
    if args.password:
        creds['password'] = args.password

    actions = {}
    if args.dbs:
        actions['list_dbs'] = {}
    if args.hashes:
        actions['list_hashes'] = {}
    if args.sql:
        actions['sql'] = {'query': args.sql}
    if args.bruteforce:
        actions['bruteforce'] ={'username_file': args.username_file, 'password_file': args.password_file, 'workers': args.bruteforce_workers}

    Output.setup()

    mysqlscan(args.targets, static_inputs, args.workers, actions, creds, args.timeout)


    DB.stop_worker()
    Output.stop()

def mysqlscan(input_targets, static_inputs, workers, actions, creds, timeout):

    args = (actions, creds, timeout)

    dispatch_targets(input_targets, static_inputs, mysqlscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
