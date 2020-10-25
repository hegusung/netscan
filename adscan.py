#!/usr/bin/python3
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.adscan.adscan import adscan_worker

def main():
    parser = argparse.ArgumentParser(description='ADScan')
    parser.add_argument('targets', type=str)
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
    #parser.add_argument("--passpol", action='store_true', help='dump password policy from Active Directory')

    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    args = parser.parse_args()

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
    #if args.passpol:
    #    actions['passpol'] = {}

    Output.setup()

    adscan(args.targets, static_inputs, args.workers, actions, creds, args.timeout)

    Output.stop()

def adscan(input_targets, static_inputs, workers, actions, creds, timeout):

    args = (actions, creds, timeout)

    dispatch_targets(input_targets, static_inputs, adscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
