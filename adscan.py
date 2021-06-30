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
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Authentication
    parser.add_argument('--null', action='store_true', help='NULL bind', dest='null')
    parser.add_argument('--guest', action='store_true', help='guest account', dest='guest')
    parser.add_argument('-u', metavar='username', type=str, nargs='?', help='Username', default=None, dest='username')
    parser.add_argument('-d', metavar='domain', type=str, nargs='?', help='Domain', default=None, dest='domain')
    parser.add_argument('--pass', metavar='password', type=str, nargs='?', help='Password', default=None, dest='password')
    parser.add_argument('--hash', metavar='ntlm hash', type=str, nargs='?', help='NTLM hash', default=None, dest='hash')
    # Enum
    parser.add_argument("--users", action='store_true', help='dump users from Active Directory')
    parser.add_argument("--groups", action='store_true', help='dump groups from Active Directory')
    parser.add_argument("--hosts", action='store_true', help='dump hosts from Active Directory')
    parser.add_argument("--dns", action='store_true', help='dump DNS entries from Active Directory')
    parser.add_argument("--gpp", action='store_true', help='Search for passwords in GPP')
    parser.add_argument("--spns", action='store_true', help='dump SPNS from Active Directory')
    parser.add_argument("--passpol", action='store_true', help='dump password policy from Active Directory')
    parser.add_argument("--trusts", action='store_true', help='dump trusts from Active Directory')
    parser.add_argument("--cacerts", action='store_true', help='List CA certificates from Active Directory')
    # Bruteforce
    parser.add_argument('--users-brute', metavar='username file', type=str, nargs='?', const='nofile', help='Check the existence of users via TGT request and prits KRB5ASREP hash is Pre-Auth is disable', default=None, dest='users_brute')
    # Dump
    parser.add_argument("--gmsa", action='store_true', help="[Admin required] Dump gMSA passwords")
    parser.add_argument("--laps", action='store_true', help="[Admin required] Dump LAPS passwords")
    parser.add_argument("--ntds", choices={'vss', 'drsuapi'}, nargs='?', const='drsuapi', help="[Admin required] dump the NTDS.dit from target DCs using the specifed method (default: drsuapi)")
    # Modules
    parser.add_argument("--list-modules", action="store_true", help="List available modules", dest='list_modules')
    parser.add_argument('-m', metavar='modules', nargs='?', type=str, help='Launch modules', default=None, dest='modules')

    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

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
        if args.domain:
            creds['domain'] = args.domain
        else:
            print('Please specify the domain (complete FQDN)')
            sys.exit()
        if args.username:
            creds['username'] = args.username
        if args.password:
            creds['password'] = args.password
        if args.hash:
            creds['hash'] = args.hash

    actions = {}
    if args.users:
        actions['users'] = {}
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
    if args.cacerts:
        actions['cacerts'] = {}
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

    Output.setup()

    adscan(targets, static_inputs, args.workers, actions, creds, args.timeout)


    DB.stop_worker()
    Output.stop()

def adscan(input_targets, static_inputs, workers, actions, creds, timeout):

    args = (actions, creds, timeout)

    dispatch_targets(input_targets, static_inputs, adscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
