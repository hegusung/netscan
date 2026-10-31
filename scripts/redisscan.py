#!/usr/bin/env python3

import argparse
from utils.utils import normalize_path
from utils.process_inputs import str_ports, port_file
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.redisscan.redisscan import redisscan_worker
from utils.db import DB
from utils.config import Config
from utils.argparse_format import ColoredSelectiveDefaultsHelpFormatter
from utils.credential_campaign import apply_mcp_credential_environment, dispatch_credential_campaign
from lib.redisscan.redis_bruteforce import bruteforce_worker



def main():
    parser = argparse.ArgumentParser(description='RedisScan', formatter_class=ColoredSelectiveDefaultsHelpFormatter)
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='6379', dest='port')
    parser.add_argument('--port-file', metavar='Port-file', nargs='?', type=port_file, help='Specify a port file', default=None, dest='port_file')
    parser.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    parser.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    
    # Bruteforce
    parser.add_argument("--bruteforce", action='store_true', help='Enable bruteforce')
    parser.add_argument("--spray", action='store_true', help='Try each password across the full target scope before the next password')
    parser.add_argument('-P', metavar='password file', type=str, nargs='?', help='Password file', default=None, dest='password_file')
    parser.add_argument('-W', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers for the bruteforce', default=5, dest='bruteforce_workers')
    parser.add_argument('--bruteforce-delay', type=int, default=0, dest='bruteforce_delay')
    parser.add_argument('--credential-jitter', type=int, default=0, dest='credential_jitter')
    parser.add_argument('--spray-round-delay', type=int, default=0, dest='spray_round_delay')
    parser.add_argument('--max-attempts-per-account', type=int, default=None, dest='max_attempts_per_account')
    parser.add_argument('--continue-on-success', action='store_true', dest='continue_on_success')
    
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers', default=10, dest='workers')
    
    # Resume
    parser.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()
    apply_mcp_credential_environment(args)
    if args.max_attempts_per_account is not None and args.max_attempts_per_account < 1:
        parser.error('--max-attempts-per-account must be greater than zero')
    if (args.bruteforce or args.spray) and args.password_file is None:
        parser.error('-P is required for a credential campaign')

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
    if args.port:
        static_inputs['port'] = args.port
    if args.port_file:
        static_inputs['port'] += normalize_path(args.port_file)

    creds = {}
    if args.password != None:
        creds['password'] = args.password

    actions = {}
    if args.bruteforce or args.spray:
        actions['bruteforce'] = {'secret_file': normalize_path(args.password_file), 'workers': args.bruteforce_workers, 'strategy': 'spray' if args.spray else 'bruteforce', 'delay': args.bruteforce_delay, 'jitter': args.credential_jitter, 'spray_round_delay': args.spray_round_delay, 'max_attempts_per_account': args.max_attempts_per_account, 'continue_on_success': args.continue_on_success}


    redisscan(targets, static_inputs, args.workers, actions, creds, args.timeout, args.delay, args.resume)

    DB.stop_worker()
    Output.stop()


def redisscan(input_targets, static_inputs, workers, actions, creds, timeout, delay, resume):
    scan_actions = dict(actions)
    campaign = scan_actions.pop('bruteforce', None)
    args = (scan_actions, creds, timeout)
    dispatch_targets(input_targets, static_inputs, redisscan_worker, args, workers=workers, delay=delay, resume=resume)
    if campaign:
        dispatch_credential_campaign(input_targets, static_inputs, campaign, bruteforce_worker, timeout=timeout, username='N/A', progress_name='Redis credentials')


if __name__ == '__main__':
    main()
