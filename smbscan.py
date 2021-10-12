#!/usr/bin/python3
import argparse
import sys

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from server.payload_manager import PayloadManager
from lib.smbscan.smbscan import smbscan_worker, smb_modules

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='SMBScan')
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='445', dest='port')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Authentication
    parser.add_argument('--null', action='store_true', help='NULL bind', dest='null')
    parser.add_argument('--guest', action='store_true', help='guest account', dest='guest')
    parser.add_argument('-u', metavar='username', type=str, nargs='?', help='Username', default=None, dest='username')
    parser.add_argument('-d', metavar='domain', type=str, nargs='?', help='Domain', default='WORKGROUP', dest='domain')
    parser.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    parser.add_argument('--hash', metavar='ntlm hash', type=str, nargs='?', help='NTLM hash', default=None, dest='hash')
    # Share-related
    parser.add_argument('--shares', action='store_true', help='List shares', dest='shares')
    parser.add_argument('--list', metavar='share', type=str, nargs='?', help='List share content', const='list_all', default=None, dest='list')
    parser.add_argument('--recurse', metavar='number of times', nargs='?', type=int, help='Number of recursions during directory listing', default=0, dest='recurse')
    # Execution-related
    parser.add_argument('--exec-method', choices={"wmiexec", "mmcexec", "smbexec", "atexec"}, default=None, help="method to execute the command. (default: wmiexec)", dest='exec_method')
    parser.add_argument("--cmd", metavar="COMMAND", help="execute the specified command", dest='command')
    parser.add_argument("--payload", metavar="PAYLOAD", help="execute the specified payload", nargs='+', dest='payload')
    parser.add_argument("--list-payloads", action='store_true', help='List payloads', dest='list_payloads')
    # Dump secrets
    parser.add_argument("--sam", action='store_true', help='dump SAM hashes from target systems')
    parser.add_argument("--lsa", action='store_true', help='dump LSA secrets from target systems')
    # Enum
    parser.add_argument("--users", action='store_true', help='dump users from target systems')
    parser.add_argument("--groups", action='store_true', help='dump groups from target systems')
    parser.add_argument("--admins", action='store_true', help='dump admins from target systems')
    parser.add_argument("--apps", action='store_true', help='dump applications list from target systems')
    parser.add_argument("--processes", action='store_true', help='dump processes list from target systems')
    parser.add_argument("--passpol", action='store_true', help='dump password policy from target systems')
    parser.add_argument("--loggedin", action='store_true', help='dump logged on users from target systems')
    parser.add_argument("--sessions", action='store_true', help='dump sessions from target systems')
    parser.add_argument("--rid-brute", metavar="range", help='RID bruteforce', type=str, default=None, dest='rid_brute')
    # Bruteforce
    parser.add_argument("--bruteforce", action='store_true', help='Enable bruteforce')
    parser.add_argument("--simple-bruteforce", action='store_true', help='Enable simple bruteforce (username=password)', dest='simple_bruteforce')
    parser.add_argument('-U', metavar='username file', type=str, nargs='?', help='Username file (format username or username:password)', default=None, dest='username_file')
    parser.add_argument('-P', metavar='password file', type=str, nargs='?', help='Password file', default=None, dest='password_file')
    parser.add_argument('-W', metavar='number worker', nargs='?', type=int, help='Number of concurent workers for the bruteforce', default=5, dest='bruteforce_workers')
    # Modules
    parser.add_argument("--list-modules", action="store_true", help="List available modules", dest='list_modules')
    parser.add_argument('-m', metavar='modules', nargs='*', type=str, help='Launch modules', default=None, dest='modules')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    # Resume
    parser.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    if args.list_modules:
        print('Available modules:')
        for module in smb_modules.list_modules():
            print('- %s   %s' % (module['name'].ljust(15), module['description']))
        sys.exit()

    if args.list_payloads:
        print('Available payloads:')
        for payload_name, payload in PayloadManager.list_payloads().items():
            print('- %s %s' % (payload.name, ' '.join(payload.args)))
        sys.exit()

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
    if args.null:
        creds['username'] = ''
        creds['password'] = ''
    elif args.guest:
        creds['username'] = 'guest'
        creds['password'] = ''
    else:
        if args.domain:
            creds['domain'] = args.domain
        if args.username:
            creds['username'] = args.username
        if args.password:
            creds['password'] = args.password
        if args.hash:
            creds['hash'] = args.hash

    actions = {}
    if args.list:
        actions['list'] = {'recurse': args.recurse}
        if args.list != 'list_all':
            actions['list']['share'] = args.list
    if args.shares:
        actions['list_shares'] = {}
    if args.command:
        actions['command'] = {'command': args.command, 'method': args.exec_method}
    if args.payload:
        cmd = PayloadManager.generate_payload(args.payload[0], args.payload[1:])
        actions['command'] = {'command': cmd, 'method': args.exec_method}
    if args.lsa:
        actions['lsa'] = {}
    if args.sam:
        actions['sam'] = {}
    if args.users:
        actions['users'] = {}
    if args.groups:
        actions['groups'] ={}
    if args.admins:
        actions['admins'] ={}
    if args.apps:
        actions['apps'] ={}
    if args.processes:
        actions['processes'] ={}
    if args.passpol:
        actions['passpol'] = {}
    if args.loggedin:
        actions['loggedin'] ={}
    if args.sessions:
        actions['sessions'] ={}
    if args.rid_brute:
        if '-' in args.rid_brute:
            start_rid = int(args.rid_brute.split('-')[0])
            end_rid = int(args.rid_brute.split('-')[-1])
        else:
            start_rid = 0
            end_rid = int(args.rid_brute)

        actions['rid_brute'] = {'start': start_rid, 'end': end_rid}
    if args.bruteforce:
        actions['bruteforce'] ={'username_file': args.username_file, 'password_file': args.password_file, 'workers': args.bruteforce_workers}
    if args.simple_bruteforce:
        actions['simple_bruteforce'] ={'username_file': args.username_file, 'workers': args.bruteforce_workers}
    if args.modules:
        actions['modules'] = {'modules': args.modules[0], 'args': args.modules[1:]}

    Output.setup()

    smbscan(targets, static_inputs, args.workers, actions, creds, args.timeout, args.resume)


    DB.stop_worker()
    Output.stop()

def smbscan(input_targets, static_inputs, workers, actions, creds, timeout, resume):

    args = (actions, creds, timeout)

    dispatch_targets(input_targets, static_inputs, smbscan_worker, args, workers=workers, resume=resume)

if __name__ == '__main__':
    main()
