#!/usr/bin/python3
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.vncscan.vncscan import vncscan_worker

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='VNCScan')
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='5900', dest='port')
    parser.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Actions
    parser.add_argument("--screenshot", action='store_true', help='Take a screenshot')
    parser.add_argument('--ducky', metavar='ducky script', type=str, nargs='?', help='Execute a ducky script', default=None, dest='ducky')
    # Bruteforce
    parser.add_argument("--bruteforce", action='store_true', help='Enable bruteforce')
    parser.add_argument('-P', metavar='password file', type=str, nargs='?', help='Password file', default=None, dest='password_file')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    Config.load_config()
    DB.start_worker(args.nodb)

    targets = {}
    if args.targets:
        targets['targets'] = args.targets
    if args.target_file:
        targets['target_file'] = args.target_file

    static_inputs = {}
    if args.port:
        static_inputs['port'] = args.port

    creds = {}
    if args.password:
        creds['password'] = args.password

    actions = {}
    if args.screenshot:
        actions['screenshot'] = {}
    if args.ducky:
        actions['ducky'] = {'ducky_script': args.ducky}
    if args.bruteforce:
        actions['bruteforce'] = {'password_file': args.password_file}

    Output.setup()

    vncscan(targets, static_inputs, args.workers, actions, creds, args.timeout)


    DB.stop_worker()
    Output.stop()

def vncscan(input_targets, static_inputs, workers, actions, creds, timeout):

    args = (actions, creds, timeout)

    dispatch_targets(input_targets, static_inputs, vncscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
