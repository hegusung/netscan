#!/usr/bin/python3
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.rdpscan.rdpscan import rdpscan_worker

def main():
    parser = argparse.ArgumentParser(description='RDPScan')
    parser.add_argument('targets', type=str)
    parser.add_argument('-d', metavar='domain', type=str, nargs='?', help='Domain', default='WORKGROUP', dest='domain')
    parser.add_argument('-u', metavar='username', type=str, nargs='?', help='Username', default=None, dest='username')
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='3389', dest='port')
    parser.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    parser.add_argument('--hash', metavar='ntlm hash', type=str, nargs='?', help='NTLM hash', default=None, dest='hash')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Actions
    # Bruteforce
    parser.add_argument("--bruteforce", action='store_true', help='Enable bruteforce')
    parser.add_argument("--simple-bruteforce", action='store_true', help='Enable simple bruteforce (username=password)', dest='simple_bruteforce')
    parser.add_argument('-U', metavar='username file', type=str, nargs='?', help='Username file (format username or username:password)', default=None, dest='username_file')
    parser.add_argument('-P', metavar='password file', type=str, nargs='?', help='Password file', default=None, dest='password_file')
    parser.add_argument('-W', metavar='number worker', nargs='?', type=int, help='Number of concurent workers for the bruteforce', default=5, dest='bruteforce_workers')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    args = parser.parse_args()

    static_inputs = {}
    if args.port:
        static_inputs['port'] = args.port

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
    if args.bruteforce:
        actions['bruteforce'] ={'username_file': args.username_file, 'password_file': args.password_file, 'workers': args.bruteforce_workers}
    if args.simple_bruteforce:
        actions['simple_bruteforce'] ={'username_file': args.username_file, 'workers': args.bruteforce_workers}

    Output.setup()

    rdpscan(args.targets, static_inputs, args.workers, actions, creds, args.timeout)

    Output.stop()

def rdpscan(input_targets, static_inputs, workers, actions, creds, timeout):

    args = (actions, creds, timeout)

    dispatch_targets(input_targets, static_inputs, rdpscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
