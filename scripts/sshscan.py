#!/usr/bin/env python3

import argparse
import sys
from utils.utils import normalize_path
from utils.process_inputs import str_ports, port_file
from utils.dispatch import dispatch, dispatch_targets
from utils.output import Output
from lib.sshscan.sshscan import sshscan_worker, ssh_modules
from utils.db import DB
from utils.config import Config
from utils.argparse_format import ColoredSelectiveDefaultsHelpFormatter
from utils.credential_campaign import (
    CampaignState,
    iter_target_credential_attempts,
    target_credential_attempt_count,
)
from lib.sshscan.ssh_bruteforce import bruteforce_worker



def main():
    parser = argparse.ArgumentParser(description='SSHScan', formatter_class=ColoredSelectiveDefaultsHelpFormatter)
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='22', dest='port')
    parser.add_argument('--port-file', metavar='Port-file', nargs='?', type=port_file, help='Specify a port file', default=None, dest='port_file')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    parser.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    
    # Authentication
    parser.add_argument('-u', metavar='username', type=str, nargs='?', help='Username', default=None, dest='username')
    parser.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    parser.add_argument('--key', metavar='ssh_key_file', type=str, nargs='?', help='Use a SSH key file', default=None, dest='key_file')
    
    # Action
    parser.add_argument('--cmd', metavar='command', type=str, nargs='?', help='Execute a command', default=None, dest='command')
    
    # Bruteforce
    parser.add_argument("--bruteforce", action='store_true', help='Enable bruteforce')
    parser.add_argument("--spray", action='store_true', help='Try each password across all users before the next password')
    parser.add_argument("--simple-bruteforce", action='store_true', help='Try username=password', dest='simple_bruteforce')
    parser.add_argument('-U', metavar='username file', type=str, nargs='?', help='Username file (format username or username:password)', default=None, dest='username_file')
    parser.add_argument('-P', metavar='password file', type=str, nargs='?', help='Password file', default=None, dest='password_file')
    parser.add_argument('-W', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers for the bruteforce', default=1, dest='bruteforce_workers')
    parser.add_argument("--bruteforce-delay", metavar='seconds', type=int, nargs='?', help='Delay between each bruteforce attempt', default=0, dest='bruteforce_delay')
    parser.add_argument('--credential-jitter', metavar='seconds', type=int, nargs='?', help='Add random delay up to this value before each attempt', default=0, dest='credential_jitter')
    parser.add_argument('--spray-round-delay', metavar='seconds', type=int, nargs='?', help='Minimum delay between complete password spray rounds', default=0, dest='spray_round_delay')
    parser.add_argument('--max-attempts-per-account', metavar='count', type=int, nargs='?', help='Limit secrets attempted for each account', default=None, dest='max_attempts_per_account')
    parser.add_argument('--continue-on-success', action='store_true', help='Continue testing an account after a successful login', dest='continue_on_success')

    # Modules
    parser.add_argument("--list-modules", action="store_true", help="List available modules", dest='list_modules')
    parser.add_argument('-m', metavar='modules', nargs='*', type=str, help='Launch modules', default=None, dest='modules')

    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers', default=10, dest='workers')
    
    # Resume
    parser.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    if args.bruteforce or args.spray or args.simple_bruteforce:
        if args.username_file is None:
            parser.error('-U is required for a credential campaign')
        if (args.bruteforce or args.spray) and args.password_file is None:
            parser.error('-P is required with --bruteforce or --spray')
        if args.max_attempts_per_account is not None and args.max_attempts_per_account < 1:
            parser.error('--max-attempts-per-account must be greater than zero')

    if args.list_modules:
        print('Available modules:')
        for module in ssh_modules.list_modules():
            print('- %s   %s' % (module['name'].ljust(15), module['description']))
        sys.exit()

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
    if args.username != None:
        creds['username'] = args.username
    if args.password != None:
        creds['password'] = args.password
    if args.key_file:
        creds['key_file'] = args.key_file

    actions = {}
    if args.command:
        actions['command'] ={'command': args.command}
    if args.bruteforce or args.spray or args.simple_bruteforce:
        actions['bruteforce'] ={
            'username_file': normalize_path(args.username_file),
            'password_file': normalize_path(args.password_file),
            'workers': args.bruteforce_workers,
            'bruteforce_delay': args.bruteforce_delay,
            'jitter': args.credential_jitter,
            'spray_round_delay': args.spray_round_delay,
            'strategy': 'spray' if args.spray else 'bruteforce',
            'simple': args.simple_bruteforce,
            'max_attempts_per_account': args.max_attempts_per_account,
            'continue_on_success': args.continue_on_success,
        }
    if args.modules:
        if not ssh_modules.check_modules(args.modules[0]):
            sys.exit()
        actions['modules'] = {'modules': args.modules[0], 'args': args.modules[1:]}


    sshscan(targets, static_inputs, args.workers, actions, creds, args.timeout, args.delay, args.resume)

    DB.stop_worker()
    Output.stop()


def sshscan(input_targets, static_inputs, workers, actions, creds, timeout, delay, resume):
    scan_actions = dict(actions)
    campaign = scan_actions.pop('bruteforce', None)
    args = (scan_actions, creds, timeout)
    dispatch_targets(input_targets, static_inputs, sshscan_worker, args, workers=workers, delay=delay, resume=resume)
    if campaign:
        options = {
            'strategy': campaign['strategy'],
            'simple': campaign['simple'],
            'max_attempts_per_account': campaign['max_attempts_per_account'],
        }
        generator = iter_target_credential_attempts(
            input_targets, static_inputs, campaign['username_file'],
            campaign.get('password_file'), **options,
        )
        size = target_credential_attempt_count(
            input_targets, static_inputs, campaign['username_file'],
            campaign.get('password_file'), **options,
        )
        state = CampaignState(
            continue_on_success=campaign['continue_on_success'],
            spray_round_delay=campaign['spray_round_delay'],
        )
        dispatch(
            generator, size, bruteforce_worker,
            (timeout, campaign['bruteforce_delay'], campaign['jitter'], state),
            workers=campaign['workers'], process=False, pg_name='SSH credentials',
        )


if __name__ == '__main__':
    main()
