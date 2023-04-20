#!/usr/bin/env python3
import argparse
import sys
import os

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
    auth_group.add_argument('-k', metavar='ticket', type=str, nargs='?', help='Kerberos authentication (uses KRB5CCNAME environement variable if not parameter is defined)', default=None, const='', dest='kerberos')
    auth_group.add_argument('--dc-ip', metavar='DC_IP', type=str, nargs='?', help='Define the DC IP for kerberos', default=None, dest='dc_ip')
    # Enum
    user_group = parser.add_argument_group("Domain user enumeration")
    user_group.add_argument("--domains", action='store_true', help='dump domains, containers and OUs from the Active Directory with some interesting parameters (Bloodhound)')
    user_group.add_argument("--users", action='store_true', help='dump users from the Active Directory, display if the account has one of the following enabled: AdminCount, Account disabled, Password not required, Password never expire, Do not require pre-auth, Trusted to auth for delegation (Bloodhound)')
    user_group.add_argument("--admins", action='store_true', help='dump users with administrative privileges from Active Directory')
    user_group.add_argument("--rdp", action='store_true', help='dump users with rdp rights from Active Directory')
    user_group.add_argument("--groups", action='store_true', help='dump groups from the Active Directory (Bloodhound)')
    user_group.add_argument("--hosts", action='store_true', help='dump hosts from the Active Directory, list if it has trusted for delegation enabled (Bloodhound)')
    user_group.add_argument("--dns", action='store_true', help='dump DNS entries from the Active Directory')
    user_group.add_argument("--gpp", action='store_true', help='Search for passwords in GPP')
    user_group.add_argument("--spns", action='store_true', help='dump SPNS from the Active Directory')
    user_group.add_argument("--passpol", action='store_true', help='dump password policy from the Active Directory')
    user_group.add_argument("--trusts", action='store_true', help='dump trusts from the Active Directory')
    user_group.add_argument("--gpos", action='store_true', help='dump GPOs from the Active Directory (Bloodhound)', dest='gpos')
    user_group.add_argument("--list-groups", metavar='username', type=str, nargs='?', help='List groups of a specific user / group', default=None, const='', dest='list_groups')
    user_group.add_argument("--list-users", metavar='groupname', type=str, nargs='?', help='List users of a specific group', default=None, dest='list_users')
    user_group.add_argument("--constrained-delegation", action='store_true', help='List constrained delegations', dest='constrained_delegation')

    acls_group = parser.add_argument_group("Enumerate ACLs/ACEs")
    acls_group.add_argument("--vuln-gpos", action='store_true', help='Extract vulnerable GPOS from Active Directory', dest='vuln_gpos')
    acls_group.add_argument("--acls", metavar='username', type=str, nargs='?', help='Extract interesting ACEs/ACLs of a user from the Active Directory', default=None, const='', dest='acls')
    acls_group.add_argument("--all-acls", metavar='username', type=str, nargs='?', help='Extract all ACEs/ACLs of a user from the Active Directory', default=None, const='', dest='acls_all')
    acls_group.add_argument("--object-acl", metavar='object', type=str, nargs='?', help='List the interesting ACLs of a specific object (LDAP DN, name or sid)', default=None, dest='object_acl')
    acls_group.add_argument("--all-object-acl", metavar='object', type=str, nargs='?', help='List all the ACLs of a specific object (LDAP DN, name or sid)', default=None, dest='object_acl_all')

    kerb_group = parser.add_argument_group("Request kerberos tickets")
    kerb_group.add_argument("--gettgt", action='store_true', help='Get a TGT ticket for the current user')
    kerb_group.add_argument("--gettgs", metavar=("SPN", "[impersonate]"), type=str, nargs='+', help='Get a TGS ticket for the specified SPN', dest='gettgs')

    adcs_group = parser.add_argument_group("ADCS")
    adcs_group.add_argument("--adcs", action='store_true', help='Discover the domain root Certificate Authority')
    adcs_group.add_argument("--ca-certs", action='store_true', help='List CA certificates from Active Directory', dest='ca_certs')
    adcs_group.add_argument("--cert-templates", action='store_true', help='List certificate templates from Active Directory', dest='cert_templates')
    adcs_group.add_argument("--esc1", metavar='username', type=str, nargs='?', help='List misconfigures certificate templates (ESC1)', default=None, const='', dest='esc1')
    adcs_group.add_argument("--esc2", metavar='username', type=str, nargs='?', help='List misconfigures certificate templates (ESC2)', default=None, const='', dest='esc2')
    adcs_group.add_argument("--esc3", metavar='username', type=str, nargs='?', help='List misconfigures certificate templates (ESC3)', default=None, const='', dest='esc3')
    adcs_group.add_argument("--esc4", metavar='username', type=str, nargs='?', help='List misconfigures certificate templates (ESC4)', default=None, const='', dest='esc4')

    # Dump
    admin_group = parser.add_argument_group("Domain admin actions")
    admin_group.add_argument("--gmsa", action='store_true', help="Dump gMSA passwords")
    admin_group.add_argument("--laps", action='store_true', help="Dump LAPS passwords")
    admin_group.add_argument("--ntds", choices={'vss', 'drsuapi'}, nargs='?', const='drsuapi', help="Dump the NTDS.dit from target DCs using the specifed method (default: drsuapi)")

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
    misc_group.add_argument("--no-ssl", action='store_true', help="Perform a LDAP connection instead of LDAPS", dest='no_ssl')
    misc_group.add_argument('--ldap-protocol', choices={"ldaps", "ldap", "gc"}, default=None, help="Way to connect to the ldap service (default: ldaps)", dest='ldap_protocol')
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
    if args.kerberos != None:
        if len(args.kerberos) != 0:
            os.environ['KRB5CCNAME'] = args.kerberos
        if not 'KRB5CCNAME' in os.environ:
            Output.error("Cannot use -k without KRB5CCNAME environment variable set")
            sys.exit()

        creds['kerberos'] = True
    if args.dc_ip != None:
        creds['dc_ip'] = args.dc_ip

    actions = {}
    if args.domains:
        actions['domains'] = {}
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
    if args.gpos:
        actions['gpos'] = {}

    if args.adcs:
        actions['casrv'] = {}
    if args.ca_certs:
        actions['ca_certs'] = {}
    if args.cert_templates:
        actions['cert_templates'] = {}
    if args.esc1 != None:
        actions['esc1'] = {'user': args.esc1}
    if args.esc2 != None:
        actions['esc2'] = {'user': args.esc2}
    if args.esc3 != None:
        actions['esc3'] = {'user': args.esc3}
    if args.esc4 != None:
        actions['esc4'] = {'user': args.esc4}

    if args.vuln_gpos:
        actions['vuln_gpos'] = {}
    if args.acls != None:
        actions['acls'] = {'user': args.acls}
    if args.acls_all != None:
        actions['acls'] = {'user': args.acls_all, 'all': True}
    if args.object_acl != None:
        actions['object_acl'] = {'object': args.object_acl}
    if args.object_acl_all != None:
        actions['object_acl'] = {'object': args.object_acl_all, 'all': True}
    if args.constrained_delegation:
        actions['constrained_delegation'] = {}
    if args.gettgt:
        actions['gettgt'] = {}
    if args.gettgs:
        actions['gettgs'] = {'spn': args.gettgs[0]}
        if len(args.gettgs) > 1:
            actions['gettgs']['impersonate'] = args.gettgs[1]
    if args.list_groups != None:
        actions['list_groups'] = {'user': args.list_groups}
    if args.list_users != None:
        actions['list_users'] = {'group': args.list_users}
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


    adscan(targets, static_inputs, args.workers, actions, creds, args.ldap_protocol, args.timeout)

    DB.stop_worker()
    Output.stop()

def adscan(input_targets, static_inputs, workers, actions, creds, no_ssl, timeout):

    args = (actions, creds, no_ssl, timeout)

    dispatch_targets(input_targets, static_inputs, adscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
