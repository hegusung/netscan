#!/usr/bin/python3
import argparse
import sys

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.adscan.adscan import adscan_worker, ad_modules

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='ADScan')
    target_group = parser.add_argument_group("Targets")
    target_group.add_argument('targets', type=str, nargs='?')
    target_group.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    # Authentication
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument('--null', action='store_true', help='NULL bind', dest='null')
    auth_group.add_argument('--guest', action='store_true', help='guest account', dest='guest')
    auth_group.add_argument('-u', metavar='username', type=str, nargs='?', help='Username', default=None, dest='username')
    auth_group.add_argument('-d', metavar='domain', type=str, nargs='?', help='Domain', default=None, dest='domain')
    auth_group.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    auth_group.add_argument('--hash', metavar='ntlm hash', type=str, nargs='?', help='NT or NTLM hash', default=None, dest='hash')
    # Enum
    user_group = parser.add_argument_group("Domain user actions")
    user_group.add_argument("--users", action='store_true', help='dump users from Active Directory, display if the account has one of the following enabled: AdminCount, Account disabled, Password not required, Password never expire, Do not require pre-auth, Trusted to auth for delegation')
    user_group.add_argument("--admins", action='store_true', help='dump users with administrative privileges from Active Directory')
    user_group.add_argument("--rdp", action='store_true', help='dump users with rdp rights from Active Directory')
    user_group.add_argument("--groups", action='store_true', help='dump groups from Active Directory')
    user_group.add_argument("--hosts", action='store_true', help='dump hosts from Active Directory, list if it has trusted for delegation enabled')
    user_group.add_argument("--dns", action='store_true', help='dump DNS entries from Active Directory')
    user_group.add_argument("--gpp", action='store_true', help='Search for passwords in GPP')
    user_group.add_argument("--spns", action='store_true', help='dump SPNS from Active Directory')
    user_group.add_argument("--passpol", action='store_true', help='dump password policy from Active Directory')
    user_group.add_argument("--trusts", action='store_true', help='dump trusts from Active Directory')
    user_group.add_argument("--casrv", action='store_true', help='Discover the domain root Certificate Authority')
    user_group.add_argument("--cacerts", action='store_true', help='List CA certificates from Active Directory')
    user_group.add_argument("--gpos", action='store_true', help='Extract vulnerable GPOS from Active Directory')
    user_group.add_argument("--acl", action='store_true', help='Extract ACEs/ACLs of the current user from Active Directory')
    user_group.add_argument("--gettgt", action='store_true', help='Get a TGT ticket for the current user')
    # Dump
    admin_group = parser.add_argument_group("Domain admin actions")
    admin_group.add_argument("--gmsa", action='store_true', help="[Admin required] Dump gMSA passwords")
    admin_group.add_argument("--laps", action='store_true', help="[Admin required] Dump LAPS passwords")
    admin_group.add_argument("--ntds", choices={'vss', 'drsuapi'}, nargs='?', const='drsuapi', help="[Admin required] dump the NTDS.dit from target DCs using the specifed method (default: drsuapi)")

    # Bruteforce
    bruteforce_group = parser.add_argument_group("Bruteforce")
    bruteforce_group.add_argument('--users-brute', metavar='username file', type=str, nargs='?', const='nofile', help='Check the existence of users via TGT request and prints KRB5ASREP hash is Pre-Auth is disabled (argument is optional if authenticated to the DC with -u)', default=None, dest='users_brute')

    # Modules
    module_group = parser.add_argument_group("Modules")
    module_group.add_argument("--list-modules", action="store_true", help="List available modules", dest='list_modules')
    module_group.add_argument('-m', metavar='modules', nargs='?', type=str, help='Launch modules ("-m all" to launch all modules)', default=None, dest='modules')

    # Misc
    misc_group = parser.add_argument_group("Misc")
    misc_group.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    misc_group.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    # Dispatcher arguments
    misc_group.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    # DB arguments
    misc_group.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    Output.setup()

    if args.list_modules:
        print('Available modules:')
        for module in ad_modules.list_modules():
            print('- %s   %s' % (module['name'].ljust(15), module['description']))
        sys.exit()

    Config.load_config()
    DB.start_worker(args.nodb)

    targets = {}
    if args.targets:
        targets['targets'] = args.targets
    if args.target_file:
        targets['target_file'] = args.target_file

    static_inputs = {}

    creds = {}
    if args.null:
        creds['username'] = ''
        creds['password'] = ''
    elif args.guest:
        creds['username'] = 'guest'
        creds['password'] = ''
    else:
        if args.username:
            creds['username'] = args.username
        if args.password:
            creds['password'] = args.password
        if args.hash:
            creds['hash'] = args.hash
    if args.domain:
        creds['domain'] = args.domain
    else:
        print('Please specify the domain (complete FQDN)')
        sys.exit()

    actions = {}
    if args.users:
        actions['users'] = {}
    if args.admins:
        actions['admins'] = {}
    if args.rdp:
        actions['rdp'] = {}
    if args.groups:
        actions['groups'] ={}
    if args.hosts:
        actions['hosts'] ={}
    if args.dns:
        actions['dns'] ={}
    if args.gpp:
        actions['gpps'] ={}
    if args.spns:
        actions['spns'] ={}
    if args.passpol:
        actions['passpol'] = {}
    if args.trusts:
        actions['trusts'] = {}
    if args.casrv:
        actions['casrv'] = {}
    if args.cacerts:
        actions['cacerts'] = {}
    if args.gpos:
        actions['gpos'] = {}
    if args.acl:
        actions['acl'] = {}
    if args.gettgt:
        actions['gettgt'] = {}
    if args.users_brute:
        actions['users_brute'] = {'username_file': args.users_brute}
    if args.gmsa:
        actions['dump_gmsa'] = {}
    if args.laps:
        actions['dump_laps'] = {}
    if args.ntds:
        actions['dump_ntds'] = {'method': args.ntds}
    if args.modules:
        module_args = {
        }
        actions['modules'] = {'modules': args.modules, 'args': module_args}


    adscan(targets, static_inputs, args.workers, actions, creds, args.timeout)

    DB.stop_worker()
    Output.stop()

def adscan(input_targets, static_inputs, workers, actions, creds, timeout):

    args = (actions, creds, timeout)

    dispatch_targets(input_targets, static_inputs, adscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
