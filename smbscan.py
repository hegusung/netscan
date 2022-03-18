#!/usr/bin/python3
import argparse
import sys
import os

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from server.payload_manager import PayloadManager
from lib.smbscan.smbscan import smbscan_worker, smb_modules

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='SMBScan')
    target_group = parser.add_argument_group("Targets")
    target_group.add_argument('targets', type=str, nargs='?')
    target_group.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    target_group.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='445', dest='port')
    # Authentication
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument('--null', action='store_true', help='NULL bind', dest='null')
    auth_group.add_argument('--guest', action='store_true', help='guest account', dest='guest')
    auth_group.add_argument('-u', metavar='username', type=str, nargs='?', help='Username', default=None, dest='username')
    auth_group.add_argument('-d', metavar='domain', type=str, nargs='?', help='Domain', default='WORKGROUP', dest='domain')
    auth_group.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    auth_group.add_argument('--hash', metavar='ntlm hash', type=str, nargs='?', help='NTLM hash', default=None, dest='hash')
    auth_group.add_argument('-k', metavar='ticket', type=str, nargs='?', help='Kerberos authentication (uses KRB5CCNAME environement variable if not parameter is defined)', default=None, const='', dest='kerberos')
    # Share-related
    share_group = parser.add_argument_group("Shared folders")
    share_group.add_argument('--shares', action='store_true', help='List shares', dest='shares')
    share_group.add_argument('--list', metavar='share', type=str, nargs='?', help='List share content', const='list_all', default=None, dest='list')
    share_group.add_argument('--recurse', metavar='number of times', nargs='?', type=int, help='Number of recursions during directory listing', default=0, dest='recurse')
    # Execution-related
    cmd_group = parser.add_argument_group("Command execution (admin rights required)")
    cmd_group.add_argument('--exec-method', choices={"wmiexec", "mmcexec", "smbexec", "atexec"}, default=None, help="method to execute the command. (default: wmiexec)", dest='exec_method')
    cmd_group.add_argument("--cmd", metavar="COMMAND", help="execute the specified command", dest='command')
    cmd_group.add_argument("--payload", metavar="PAYLOAD", help="execute the specified payload", nargs='+', dest='payload')
    cmd_group.add_argument("--list-payloads", action='store_true', help='List payloads', dest='list_payloads')
    # Dump secrets
    secrets_group = parser.add_argument_group("Secrets dumping (admin rights required)")
    secrets_group.add_argument("--sam", action='store_true', help='dump SAM hashes from target systems')
    secrets_group.add_argument("--lsa", action='store_true', help='dump LSA secrets from target systems')
    # Enum
    enum_group = parser.add_argument_group("Enumerate the target")
    enum_group.add_argument("--users", action='store_true', help='dump users from target systems')
    enum_group.add_argument("--groups", action='store_true', help='dump groups from target systems')
    enum_group.add_argument("--admins", action='store_true', help='dump admins from target systems')
    enum_group.add_argument("--apps", action='store_true', help='dump applications list from target systems')
    enum_group.add_argument("--processes", action='store_true', help='dump processes list from target systems')
    enum_group.add_argument("--passpol", action='store_true', help='dump password policy from target systems')
    enum_group.add_argument("--loggedin", action='store_true', help='dump logged on users from target systems')
    enum_group.add_argument("--sessions", action='store_true', help='dump sessions from target systems')
    enum_group.add_argument("--rid-brute", metavar="range", help='RID bruteforce', type=str, default=None, dest='rid_brute')
    # Bruteforce
    bruteforce_group = parser.add_argument_group("Bruteforce")
    bruteforce_group.add_argument("--bruteforce", action='store_true', help='Enable bruteforce')
    bruteforce_group.add_argument("--simple-bruteforce", action='store_true', help='Enable simple bruteforce (username=password)', dest='simple_bruteforce')
    bruteforce_group.add_argument('-U', metavar='username file', type=str, nargs='?', help='Username file (format username or username:password)', default=None, dest='username_file')
    bruteforce_group.add_argument('-P', metavar='password file', type=str, nargs='?', help='Password file', default=None, dest='password_file')
    bruteforce_group.add_argument('-W', metavar='number worker', nargs='?', type=int, help='Number of concurent workers for the bruteforce', default=5, dest='bruteforce_workers')
    # Modules
    module_group = parser.add_argument_group("Modules")
    module_group.add_argument("--list-modules", action="store_true", help="List available modules", dest='list_modules')
    module_group.add_argument('-m', metavar='modules', nargs='*', type=str, help='Launch modules ("-m all" to launch all modules)', default=None, dest='modules')
    
    misc_group = parser.add_argument_group("Misc")
    misc_group.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    misc_group.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    # Dispatcher arguments
    misc_group.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    # Resume
    misc_group.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    # DB arguments
    misc_group.add_argument("--nodb", action="store_true", help="Do not add entries to database")

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
    if args.kerberos != None:
        if len(args.kerberos) != 0:
            os.environ['KRB5CCNAME'] = args.kerberos
        creds['kerberos'] = True

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

    smbscan(targets, static_inputs, args.workers, actions, creds, args.timeout, args.delay, args.resume)


    DB.stop_worker()
    Output.stop()

def smbscan(input_targets, static_inputs, workers, actions, creds, timeout, delay, resume):

    args = (actions, creds, timeout)

    dispatch_targets(input_targets, static_inputs, smbscan_worker, args, workers=workers, delay=delay, resume=resume)

if __name__ == '__main__':
    main()
