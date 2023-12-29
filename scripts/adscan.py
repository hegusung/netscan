#!/usr/bin/env python3

import argparse
import sys
import os
from utils.utils import check_ip, normalize_path
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
    auth_group.add_argument('-k', metavar='ticket', type=str, nargs='?', help='Kerberos authentication (uses KRB5CCNAME environment variable if not parameter is defined)', default=None, const='', dest='kerberos')
    auth_group.add_argument('--dc-ip', metavar='DC_IP', type=str, nargs='?', help='Define the DC IP for kerberos', default=None, dest='dc_ip')
    
    # Enum
    user_group = parser.add_argument_group("Domain enumeration")
    user_group.add_argument("--domains", action='store_true', help='dump domains, containers and OUs from the Active Directory with some interesting parameters (Bloodhound)')
    user_group.add_argument("--users", action='store_true', help='dump users from the Active Directory, display if the account has one of the following enabled: AdminCount, Account disabled, Password not required, Password never expire, Do not require pre-auth, Trusted to auth for delegation (Bloodhound)')
    user_group.add_argument("--admins", action='store_true', help='dump users with administrative privileges from Active Directory')
    user_group.add_argument("--rdp", action='store_true', help='dump users with rdp rights from Active Directory')
    user_group.add_argument("--groups", action='store_true', help='dump groups from the Active Directory (Bloodhound)')
    user_group.add_argument("--hosts", action='store_true', help='dump hosts from the Active Directory, list if it has trusted for delegation enabled (Bloodhound)')
    user_group.add_argument("--dns", action='store_true', help='dump DNS entries from the Active Directory')
    user_group.add_argument("--passpol", action='store_true', help='dump password policy from the Active Directory')
    user_group.add_argument("--trusts", action='store_true', help='dump trusts from the Active Directory')
    user_group.add_argument("--gpos", action='store_true', help='dump GPOs from the Active Directory (Bloodhound)', dest='gpos')
    user_group.add_argument("--list-groups", metavar='username', type=str, nargs='?', help='List groups of a specific user / group', default=None, const='', dest='list_groups')
    user_group.add_argument("--list-users", metavar='groupname', type=str, nargs='?', help='List users of a specific group', default=None, dest='list_users')
    user_group.add_argument("--constrained-delegation", action='store_true', help='List constrained delegations', dest='constrained_delegation')

    # AD modifications
    modif_group = parser.add_argument_group("Domain modification")
    modif_group.add_argument("--add-to-group", metavar=("GroupDN", "UserDN"), type=str, nargs=2, help='Add a user to a group', dest='group_add')
    modif_group.add_argument("--del-from-group", metavar=("GroupDN", "UserDN"), type=str, nargs=2, help='Remove a user from a group', dest='group_del')
    modif_group.add_argument("--set-owner", metavar=("PrincipalDN", "TargetDN"), type=str, nargs=2, help='Modify the Target object to set the Principal as the owner', dest='set_owner')
    modif_group.add_argument("--add-ace", metavar=("PrincipalDN", "Right", "TargetDN"), type=str, nargs=3, help='Modify the Target object to add an ACE for the Principal', dest='add_ace')
    modif_group.add_argument("--restore-acl", metavar=("ACLfile",), type=str, nargs=1, help='Remove a user from a group', dest='restore_acl')
    modif_group.add_argument("--add-computer", metavar=("ComputerName", "Password"), type=str, nargs=2, help='Add a computer to the domain', dest='add_computer')
    modif_group.add_argument("--del-object", metavar=("ObjectDN",), type=str, nargs=1, help='Delete a LDAP entry from the domain', dest='del_object')
    modif_group.add_argument("--set-password", metavar=("ObjectDN", "Password"), type=str, nargs=2, help='Change a user or computer Password', dest='set_password')
    modif_group.add_argument("--add-parameter", metavar=("ObjectDN", "Parameter", "Value"), type=str, nargs=3, help='Add a new parameter to the parameter list', dest='add_parameter')
    modif_group.add_argument("--replace-parameter", metavar=("ObjectDN", "Parameter", "Value"), type=str, nargs=3, help='Replace the parameter value', dest='replace_parameter')
    modif_group.add_argument("--delete-parameter", metavar=("ObjectDN", "Parameter", "Value"), type=str, nargs=3, help='Delete a value froma parameter', dest='delete_parameter')

    # Attack
    attk_group = parser.add_argument_group("Attacks")
    attk_group.add_argument("--kerberoasting", action='store_true', help='Execute a kerberoasting attack on the accounts with a SPN')
    attk_group.add_argument("--asreproasting", action='store_true', help='Execute a ASREP-roasting attack on the accounts with "Dot not require pre-auth" flag enabled')
    attk_group.add_argument("--gpp", action='store_true', help='Search for passwords in GPP')

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
    adcs_group.add_argument("--certipy", action='store_true', help='Execute certipy', dest='certipy')
    adcs_group.add_argument("--cert-templates", action='store_true', help='List certificate templates from Active Directory', dest='cert_templates')

    # Dump
    admin_group = parser.add_argument_group("Domain admin actions")
    admin_group.add_argument("--gmsa", action='store_true', help="Dump gMSA passwords")
    admin_group.add_argument("--smsa", action='store_true', help="Dump sMSA passwords")
    admin_group.add_argument("--laps", action='store_true', help="Dump LAPS passwords")
    admin_group.add_argument("--ntds", choices={'vss', 'drsuapi'}, nargs='?', const='drsuapi', help="Dump the NTDS.dit from target DCs using the specifed method (default: drsuapi)")

    # Bruteforce
    bruteforce_group = parser.add_argument_group("Bruteforce")
    bruteforce_group.add_argument('--users-brute', metavar='username file', type=str, nargs='?', const='nofile', help='Check the existence of users via TGT request and prints KRB5ASREP hash is Pre-Auth is disabled (argument is optional if authenticated to the DC with -u)', default=None, dest='users_brute')

    # Modules
    module_group = parser.add_argument_group("Modules")
    module_group.add_argument("--list-modules", action="store_true", help="List available modules", dest='list_modules')
    module_group.add_argument('-m', metavar='modules', nargs='*', type=str, help='Launch modules', default=None, dest='modules')

    # Misc
    misc_group = parser.add_argument_group("Misc")
    misc_group.add_argument('--target-domain', metavar='domain', nargs='?', type=str, help='Target domain to request for cross-domain enumeration', dest='target_domain')
    misc_group.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    misc_group.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    misc_group.add_argument("--no-ssl", action='store_true', help="Perform a LDAP connection instead of LDAPS", dest='no_ssl')
    misc_group.add_argument('--ldap-protocol', choices={"ldaps", "ldap", "gc"}, default=None, help="Way to connect to the ldap service (default: ldaps)", dest='ldap_protocol')
    misc_group.add_argument("--python-ldap", action='store_true', help="Use python-ldap3 instead of impacket's ldap library", dest='python_ldap')
    
    # Dispatcher arguments
    misc_group.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers', default=10, dest='workers')
    
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
    DB.save_start()

    targets = {}
    if args.targets:
        targets['targets'] = args.targets
    if args.target_file:
        targets['target_file'] = normalize_path(args.target_file)

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

    if args.kerberos != None:
        if len(args.kerberos) != 0:
            os.environ['KRB5CCNAME'] = args.kerberos
        if not 'KRB5CCNAME' in os.environ:
            Output.error("Cannot use -k without KRB5CCNAME environment variable set")
            sys.exit()

        creds['kerberos'] = True
    if args.dc_ip != None:
        creds['dc_ip'] = args.dc_ip
        
    target_domain = None
    if args.target_domain != None:
        target_domain = args.target_domain
    elif 'domain' in creds:
        target_domain = creds['domain']
        
    if target_domain == None:
        print('Please specify the domain (complete FQDN) with -d or --target-domain')
        sys.exit()
        

    actions = {'target_domain': target_domain}
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
    if args.kerberoasting:
        actions['kerberoasting'] ={}
    if args.asreproasting:
        actions['asreproasting'] ={}
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
    if args.certipy:
        actions['certipy'] = {}
    if args.cert_templates:
        actions['cert_templates'] = {}

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
    if args.smsa:
        actions['dump_smsa'] = {}
    if args.laps:
        actions['dump_laps'] = {}
    if args.ntds:
        actions['dump_ntds'] = {'method': args.ntds}
    if args.group_add:
        actions['group_add'] = {'group': args.group_add[0], 'user': args.group_add[1]}
    if args.group_del:
        actions['group_del'] = {'group': args.group_del[0], 'user': args.group_del[1]}
    if args.set_owner:
        actions['set_owner'] = {'principal': args.set_owner[0], 'target': args.set_owner[1]}
    if args.add_ace:
        actions['add_ace'] = {'principal': args.add_ace[0], 'right': args.add_ace[1], 'target': args.add_ace[2]}
    if args.restore_acl:
        actions['restore_acl'] = {'file': args.restore_acl[0]}
    if args.add_computer:
        actions['add_computer'] = {'computer_name': args.add_computer[0], 'computer_password': args.add_computer[1]}
    if args.del_object:
        actions['del_object'] = {'object_dn': args.del_object[0]}
    if args.set_password:
        actions['set_password'] = {'object_dn': args.set_password[0], 'password': args.set_password[1]}
    if args.add_parameter:
        actions['add_parameter'] = {'object_dn': args.add_parameter[0], 'parameter': args.add_parameter[1], 'value': args.add_parameter[2]}
    if args.replace_parameter:
        actions['replace_parameter'] = {'object_dn': args.replace_parameter[0], 'parameter': args.replace_parameter[1], 'value': args.replace_parameter[2]}
    if args.delete_parameter:
        actions['delete_parameter'] = {'object_dn': args.delete_parameter[0], 'parameter': args.delete_parameter[1], 'value': args.delete_parameter[2]}
    if args.modules:
        if not ad_modules.check_modules(args.modules[0]):
            sys.exit()
        actions['modules'] = {'modules': args.modules[0], 'args': args.modules[1:]}


    adscan(targets, static_inputs, args.workers, actions, creds, args.ldap_protocol, args.timeout, args.python_ldap)

    DB.stop_worker()
    Output.stop()


def adscan(input_targets, static_inputs, workers, actions, creds, no_ssl, timeout, python_ldap):
    args = (actions, creds, no_ssl, python_ldap, timeout)
    dispatch_targets(input_targets, static_inputs, adscan_worker, args, workers=workers)


if __name__ == '__main__':
    main()
