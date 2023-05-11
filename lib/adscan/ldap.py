#import ldap3
from impacket.ldap import ldap, ldapasn1
import OpenSSL
import re
import binascii
import traceback
import base64
import sys
from datetime import datetime
from utils.structure import Structure
from Cryptodome.Hash import MD4
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.backends.openssl.dsa import _DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePublicKey
import impacket
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA
from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import Sequence, OctetString, Integer, SetOf
from ldap3.protocol.controls import build_control
from impacket.ldap.ldaptypes import LDAP_SID
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.ldap.ldapasn1 import Scope
from impacket.ldap.ldap import LDAPSearchError

from lib.adscan.accesscontrol import parse_accesscontrol, parse_sd, process_sid
from lib.adscan.ou import OU
from lib.adscan.gpo import GPO

from utils.output import Output

class LDAPScan:

    def __init__(self, hostname, timeout, protocol='ldap'):
        self.hostname = hostname
        #self.port = port
        self.timeout = timeout
        self.protocol = protocol
        self.ssl = protocol in ['ldaps']

        self.conn = None

        self.username = None

        self.dn_to_sid_dict = {}
        self.sid_type_dict = {
            'S-1-0-0': 'Group',
            'S-1-1-0': 'Group',
            'S-1-2-0': 'Group',
            'S-1-2-1': 'Group',
            'S-1-3-0': 'User',
            'S-1-3-1': 'User',
            'S-1-3-4': 'User',
            'S-1-5-18': 'User',
        }

    def url(self):
        """
        method = "ldaps" if self.ssl else "ldap"
        url = "%s://%s" % (method, self.hostname)
        if self.ssl and not self.port == 636:
            url += ":%d" % self.port
        if not self.ssl and not self.port == 389:
            url += ":%d" % self.port
        #url = "gc://%s" % self.hostname
        """
        url = "%s://%s" % (self.protocol, self.hostname)
        return url

    def connect(self, domain, username='', password='', ntlm='', doKerberos=False, dc_ip=None):

        # Create the baseDN
        domainParts = domain.split('.')
        self.defaultdomainnamingcontext = ''
        for i in domainParts:
            self.defaultdomainnamingcontext += 'DC=%s,' % i
        # Remove last ','
        self.defaultdomainnamingcontext = self.defaultdomainnamingcontext[:-1]

        lm_hash = ''
        nt_hash = ''
        if ntlm != None and len(ntlm) != 0:
            if not ':' in ntlm:
                nt_hash = ntlm
                lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
            else:
                nt_hash = ntlm.split(':')[1]
                lm_hash = ntlm.split(':')[0]
        
        try:
            self.conn = ldap.LDAPConnection(self.url(), self.defaultdomainnamingcontext, dc_ip)

            if doKerberos is not True:
                if username == None:
                    # Anonymous connection
                    #self.conn = ldap3.Connection(self.server)
                    self.conn.login('', '', domain, '', '')
                elif domain != None:
                    #self.conn = ldap3.Connection(self.server, user="%s\\%s" % (domain, username), password=password, authentication="NTLM")
                    self.conn.login(username, password, domain, lm_hash, nt_hash)

                    self.username = username
                    self.domain = domain
            else:
                self.conn.kerberosLogin(username, password, domain, lm_hash, nt_hash, None, dc_ip)

            self.username = username
            self.domain = domain
            self.password = password
            self.lm_hash = lm_hash
            self.nt_hash = nt_hash
            self.do_kerberos = doKerberos
            self.dc_ip = dc_ip

            self.domain_sid = None

            res = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter='(distinguishedName=%s)' % self.defaultdomainnamingcontext, attributes=['objectSid'])
            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                for attribute in item['attributes']:
                    if str(attribute['type']) == 'objectSid':
                        self.domain_sid = LDAP_SID(bytes(attribute['vals'][0])).formatCanonical()

            if self.domain_sid == None:
                Output.error({"target": self.url(), "message": "Unable to discover domain SID"})

            return True, {'default_domain_naming_context': self.defaultdomainnamingcontext, 'domain_sid': self.domain_sid}
        except impacket.ldap.ldap.LDAPSessionError as e:
            return False, None
        except impacket.ldap.ldap.LDAPSearchError as e:
            return False, None
        except OpenSSL.SSL.SysCallError as e:
            raise e
        except Exception as e:
            print("%s: %s\n%s" % (type(e), e, traceback.format_exc()))
            return False, None

    def disconnect(self):
        #if self.conn.bind():
        self.conn.close()

        self.conn = None

    def to_dict(self, item):
        item_dict = {}
        for attribute in item['attributes']:
            if len(attribute['vals']) == 1:
                item_dict[str(attribute['type'])] = attribute['vals'][0]
            else:
                item_dict[str(attribute['type'])] = attribute['vals']

        return item_dict

    def getUnixTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def list_domains(self, smbscan, callback):

        schema_guid_dict = self._get_schema_guid_dict(['domain', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name'])

        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        attributes = ['distinguishedName', 'name', 'objectSid', 'nTSecurityDescriptor', 'ms-DS-MachineAccountQuota', 'gPLink', 'msDS-Behavior-Version']
        sbase = "%s" % self.defaultdomainnamingcontext
        resp = self.conn.search(searchBase=sbase, searchFilter='(objectCategory=domain)', searchControls=[sc], attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            domain_sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical() if 'objectSid' in attr else None
            dn = str(attr['distinguishedName'])

            parameters = {}
            if 'ms-DS-MachineAccountQuota' in attr:
                parameters['ms-DS-MachineAccountQuota'] = int(attr['ms-DS-MachineAccountQuota'])

            affected_computers = [{"ObjectType": "computer", "ObjectIdentifier": sid} for sid in self._resolve_affected_computers(dn, domain_sid)]

            # Resolve child objects 
            child_objects = self._resolve_child_objects(dn)

            trusts = self._resolve_trusts(domain)

            links = {}
            gpo_paths = []
            for l in str(attr['gPLink']).split(']'):
                if len(l) == 0:
                    continue
                # Remove initial [
                l = l[1:]
                # Take after ://
                l = l.split('://')[-1]
                # Take before ;
                status = l.split(';')[1]
                link = l.split(';')[0]

                # 1 and 3 represent Disabled, Not Enforced and Disabled, Enforced respectively.
                if status in ['1', '3']:
                    continue

                links[link.lower()] = {'IsEnforced': False if status == '0' else True}

            for link_dn, link_guid_path in self._resolve_links(links.keys()).items():
                links[link_dn.lower()]['GUID'] = link_guid_path[0].upper()
                gpo_paths.append((link_guid_path[1], link_dn))

            # Resolve GPO effects
            gpo_effect = {}
            for sid in OU.privileged_sid_dict:
                gpo_effect[sid] = {}
                for t in ['Memberof', 'Members', 'Localgroup']:
                    gpo_effect[sid][t] = []

            for gpo_path, gpo_dn in gpo_paths:
                GPO.resolve_effect(smbscan, self, gpo_dn, gpo_path, gpo_effect)
            gpo_effect = GPO.merge_gpo_effect(gpo_effect)

            aces = parse_sd(bytes(attr['nTSecurityDescriptor']), domain.upper(), 'domain', schema_guid_dict)
            aces = self._resolve_sid_types(aces, 'aces')

            if 'msDS-Behavior-Version' in attr:
                level = int(str(attr['msDS-Behavior-Version']))
                functional_levels = {
                    0: "2000 Mixed/Native",
                    1: "2003 Interim",
                    2: "2003",
                    3: "2008",
                    4: "2008 R2",
                    5: "2012",
                    6: "2012 R2",
                    7: "2016"
                }
                if level in functional_levels:
                    functional_level = functional_levels[level]
                else:
                    functional_level = "Unknown"
            else:
                functional_level = "Unknown"


            callback({
                'domain': domain,
                'name': str(attr['name']),
                'parameters': parameters,
                'sid': domain_sid,
                'dn': dn,
                'functionallevel': functional_level,
                'affected_computers': affected_computers,
                'child_objects': child_objects,
                'trusts': trusts,
                'links': list(links.values()),
                'gpo_effect': gpo_effect,
                'aces': aces,
            })


    def list_containers(self, domain, callback):

        schema_guid_dict = self._get_schema_guid_dict(['container', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name'])

        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        attributes = ['name', 'distinguishedName', 'nTSecurityDescriptor', 'objectGUID']
        sbase = "%s" % self.defaultdomainnamingcontext
        resp = self.conn.search(searchBase=sbase, searchFilter='(objectCategory=container)', searchControls=[sc], attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            container_domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])

            if container_domain.lower() != domain.lower():
                return

            dn = str(attr['distinguishedName'])

            b = bytes(attr['objectGUID'])
            guid = b[0:4][::-1].hex() + '-'
            guid += b[4:6][::-1].hex() + '-'
            guid += b[6:8][::-1].hex() + '-'
            guid += b[8:10].hex() + '-'
            guid += b[10:16].hex()


            # Resolve child objects 
            child_objects = self._resolve_child_objects(dn)

            aces = parse_sd(bytes(attr['nTSecurityDescriptor']), domain.upper(), 'container', schema_guid_dict)
            aces = self._resolve_sid_types(aces, 'aces')

            callback({
                'domain': domain,
                'name': str(attr['name']),
                'dn': dn,
                'guid': guid,
                'child_objects': child_objects,
                'aces': aces,
            })



    def _get_schema_guid_dict(self, parameters):

        # We need a LDAP connection and not a GC
        if self.protocol == "gc":
            for ldap_protocol in ['ldaps', 'ldap']:
                success = False
                try:
                    ldap_conn = LDAPScan(self.hostname, self.timeout, protocol=ldap_protocol)
                    success, ldap_info = ldap_conn.connect(self.domain, self.username, self.password, "%s:%s" % (self.lm_hash, self.nt_hash), self.do_kerberos, self.dc_ip)

                    if success:
                        break
                except OpenSSL.SSL.SysCallError as e:
                    pass
            else:
                Output.minor({'target': ldapscan.url(), 'message': 'LDAP: Unable to connect to LDAP'})
        else:
            ldap_conn = self

        _, schema_guid_dict = ldap_conn.generate_guid_dict(all=False, parameters=parameters)

        if self.protocol == "gc":
            ldap_conn.disconnect()

        return schema_guid_dict

    def list_ous(self, smbscan, domain, domain_sid, callback):
        OU.list(self, smbscan, domain, domain_sid, callback)

    def _resolve_name_to_sid(self, domain, name):
        if "\\" in name:
            account_domain = name.split("\\")[0]
            if "." in account_domain:
                domain = account_domain
            else:
                # TODO: try to resolve better
                return None
            name = name.split("\\")[-1]

        # Child object
        search_filter = "(|(name=%s)(sAMAccountName=%s))" % (name, name)
        search_base = ",".join(["DC=%s" % dc for dc in domain.split('.')])

        sc = ldap.SimplePagedResultsControl(size=10)
        attributes = ['distinguishedName', 'objectSid']
        res = self.conn.search(searchBase=search_base, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

        return_sid = None

        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            attr = self.to_dict(item)

            if 'objectSid' in attr:
                return_sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()
                break

        return return_sid

    def list_gpos(self, callback):

        GPO.list(self, callback)

    def _resolve_child_objects(self, searchBase):
        childs = []
        
        # Child object
        search_filter = "(|(cn=*)(ou=*))"

        sc = ldap.SimplePagedResultsControl(size=10)
        attributes = ['distinguishedName', 'objectClass', 'objectGUID', 'objectSid']
        try:
            res = self.conn.search(searchBase=searchBase, searchFilter=search_filter, searchControls=[sc], attributes=attributes, scope=Scope('singleLevel'))
        except LDAPSearchError as e:
            try:
                res = self.conn.search(searchBase=searchBase.encode('latin1').decode(), searchFilter=search_filter, searchControls=[sc], attributes=attributes, scope=Scope('singleLevel'))
            except LDAPSearchError as e:
                Output.error("Unable to query childs: %s: %s" % (searchBase, str(e)))
                res = []

        #print("==============================================================")
        #print(searchBase)

        domain = None
        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            attr = self.to_dict(item)

            #print(attr['distinguishedName'])
            try:
                domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            except KeyError:
                continue

            class_list = [] 
            if 'objectClass' in attr:
                if type(attr['objectClass']) != SetOf:
                    attr['objectClass'] = [attr['objectClass']]

                for c in attr['objectClass']:
                    class_list.append(str(c))

            if 'user' in class_list:
                child_class = "User"
            elif 'group' in class_list:
                child_class = "Group"
            elif 'computer' in class_list:
                child_class = "Computer"
            elif 'container' in class_list:
                child_class = "Container"
            elif 'organizationalUnit' in class_list:
                child_class = "OU"
            else:
                child_class = "Base"

            if 'objectSid' in attr:
                obj_id = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()
                obj_id = process_sid(domain, obj_id)
            else:
                b = bytes(attr['objectGUID'])
                guid = b[0:4][::-1].hex() + '-'
                guid += b[4:6][::-1].hex() + '-'
                guid += b[6:8][::-1].hex() + '-'
                guid += b[8:10].hex() + '-'
                guid += b[10:16].hex()

                obj_id = guid.upper()

            childs.append({"ObjectIdentifier": obj_id, "ObjectType": child_class})

        return childs

    def _resolve_trusts(self, domain_name):
        trusts = []
        
        # Child object
        search_filter = "(objectClass=trustedDomain)"

        sc = ldap.SimplePagedResultsControl(size=10)
        attributes = ['distinguishedName', 'name', 'trustDirection', 'trustType', 'trustAttributes', 'securityIdentifier']
        res = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter=search_filter, searchControls=[sc], attributes=attributes)


        domain = None
        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            attr = self.to_dict(item)

            if str(attr['name']).lower() == domain_name.lower():
                continue

            attr['trustAttributes'] = int(str(attr['trustAttributes']))
            if attr['trustAttributes'] & 0x20 != 0: # Within forest
                trusttype = 'ParentChild'
                is_transitive = True
                sid_filtering = (attr['trustAttributes'] & 0x4) != 0 # Qurantined domain
            elif attr['trustAttributes'] & 0x8 != 0: # Forest transitive
                trusttype = 'Forest'
                is_transitive = True
                sid_filtering = True
            elif attr['trustAttributes'] & 0x40 != 0 or attr['trustAttributes'] & 0x10 != 0: # Treat as external or Cross organisation
                trusttype = 'External'
                is_transitive = False
                sid_filtering = True
            else:
                trusttype = 'Unknown'
                is_transitive = (attr['trustAttributes'] & 0x1) != 0 # Non_transitive
                sid_filtering = True


            domain_sid = LDAP_SID(bytes(attr['securityIdentifier'])).formatCanonical() if 'securityIdentifier' in attr else None

            trusts.append({
                "TargetDomainSid": domain_sid,
                "TargetDomainName": str(attr['name']).upper(),
                "TrustDirection": int(str(attr['trustDirection'])),
                "TrustType": trusttype,
                "SidFilteringEnabled": sid_filtering,
                "IsTransitive": is_transitive,
            })

        return trusts



    def _resolve_affected_computers(self, searchBase, domain_sid):
        computers = []
        
        # Computers
        search_filter = "(samaccounttype=805306369)"

        sc = ldap.SimplePagedResultsControl(size=10)
        attributes = ['distinguishedName', 'objectSid']
        try:
            res = self.conn.search(searchBase=searchBase, searchFilter=search_filter, searchControls=[sc], attributes=attributes)
        except LDAPSearchError:
            try:
                res = self.conn.search(searchBase=searchBase.encode('latin1').decode(), searchFilter=search_filter, searchControls=[sc], attributes=attributes)
            except LDAPSearchError as e:
                Output.error("Unable to query computers: %s: %s" % (searchBase, str(e)))
                res = []


        domain = None
        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            attr = self.to_dict(item)

            if not 'objectSid' in attr:
                continue

            sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()

            if sid.startswith(domain_sid):
                computers.append(sid)

        return computers



    def _resolve_links(self, links_dn_list):
        links_dict = {}
        
        if len(links_dn_list) != 0:
            search_filter = "(|%s)" % "".join(["(distinguishedName=%s)" % dn for dn in links_dn_list])

            sc = ldap.SimplePagedResultsControl(size=10)
            attributes = ['distinguishedName', 'objectGUID', 'gPCFileSysPath']
            try:
                res = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter=search_filter, searchControls=[sc], attributes=attributes)
            except impacket.ldap.ldap.LDAPSearchError as e:
                Output.error("Unable to query: %s: %s" % (search_filter, str(e)))
                return links_dict

            domain = None
            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                attr = self.to_dict(item)

                if not 'objectGUID' in attr:
                    continue
                if not 'gPCFileSysPath' in attr:
                    continue

                b = bytes(attr['objectGUID'])
                guid = b[0:4][::-1].hex() + '-'
                guid += b[4:6][::-1].hex() + '-'
                guid += b[6:8][::-1].hex() + '-'
                guid += b[8:10].hex() + '-'
                guid += b[10:16].hex()

                links_dict[str(attr['distinguishedName'])] = (guid, str(attr['gPCFileSysPath']))

        return links_dict

    def _resolve_sid_types(self, data, data_type):
        to_process = []
        if data_type == 'aces':
            for obj in data['aces']:
                sid = "S-" + obj['PrincipalSID'].split('S-')[-1]
                if not sid in self.sid_type_dict:
                    to_process.append(sid)
        elif data_type == 'members':
            for sid in data:
                sid = "S-" + sid.split('S-')[-1]
                if not sid in self.sid_type_dict:
                    to_process.append(sid)
        elif data_type == 'gpo_effect':
            for t, group in data.items():
                for groupname, members in group.items():
                    for member in members:
                        sid = member['ObjectIdentifier']
                        sid = "S-" + sid.split('S-')[-1]
                        if not 'ObjectType' in member and not sid in self.sid_type_dict:
                            to_process.append(sid)

        if len(to_process) != 0:

            search_filter = "(|%s)" % "".join(["(objectSid=%s)" % sid for sid in to_process])

            sc = ldap.SimplePagedResultsControl(size=10)
            attributes = ['objectSid', 'objectClass']
            res = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

            domain = None
            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                attr = self.to_dict(item)

                if not 'objectSid' in attr:
                    continue

                sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()

                class_list = [] 
                if 'objectClass' in attr:
                    if type(attr['objectClass']) != SetOf:
                        attr['objectClass'] = [attr['objectClass']]

                    for c in attr['objectClass']:
                        class_list.append(str(c).lower())

                if 'user' in class_list:
                    self.sid_type_dict[sid] = 'User'
                elif 'computer' in class_list:
                    self.sid_type_dict[sid] = 'Computer'
                elif 'group' in class_list:
                    self.sid_type_dict[sid] = 'Group'
                else:
                    self.sid_type_dict[sid] = 'Base'

        if data_type == 'aces':
            for obj in data['aces']:
                sid = "S-" + obj['PrincipalSID'].split('S-')[-1]
                if sid in self.sid_type_dict:
                    obj['PrincipalType'] = self.sid_type_dict[sid]
                else:
                    self.sid_type_dict[sid] = 'Base'
                    obj['PrincipalType'] = 'Base'
        elif data_type == 'members':
            new_data = []
            for sid in data:
                raw_sid = "S-" + sid.split('S-')[-1]
                if raw_sid in self.sid_type_dict:
                    new_data.append({
                        'ObjectIdentifier': sid,
                        'ObjectType': self.sid_type_dict[raw_sid],
                    })
                else:
                    self.sid_type_dict[raw_sid] = 'Base'
                    new_data.append({
                        'ObjectIdentifier': sid,
                        'ObjectType': self.sid_type_dict[raw_sid],
                    })

            data = new_data
        elif data_type == 'gpo_effect':
            for t, group in data.items():
                for groupname, members in group.items():
                    for member in members:
                        sid = member['ObjectIdentifier']
                        sid = "S-" + sid.split('S-')[-1]
                        if not 'ObjectType' in member:
                            if sid in self.sid_type_dict:
                                member['ObjectType'] = self.sid_type_dict[sid]
                            else:
                                member['ObjectType'] = 'Base'


        return data


    def list_users(self, callback):

        schema_guid_dict = self._get_schema_guid_dict(['user', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name'])

        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        attributes = ['distinguishedName', 'sAMAccountName', 'displayName', 'description', 'objectSid', 'primaryGroupID', 'whenCreated', 'lastLogon', 'pwdLastSet', 'userAccountControl', 'adminCount', 'memberOf', 'nTSecurityDescriptor', 'msDS-GroupMSAMembership', 'servicePrincipalName']
        sbase = "%s" % self.defaultdomainnamingcontext
        search_filter = '(|(objectCategory=user)(objectCategory=CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=main,DC=local))'
        #resp = self.conn.search(searchBase=sbase, searchFilter='(|(objectCategory=user)(objectCategory=CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=main,DC=local))', searchControls=[sc], attributes=attributes, sizeLimit=0)
        #self.conn.search(searchBase=sbase, searchFilter='(samaccounttype=805306368)', searchControls=[sc, sc2], perRecordCallback=process, attributes=attributes)

        from ldap3 import Server, Connection, SUBTREE, ALL
        from ldap3.protocol.microsoft import security_descriptor_control
        s = Server(self.hostname, port=636, use_ssl=True, get_info=ALL)  # define an unsecure LDAP server, requesting info on DSE and schema
        user = "%s@%s" % (self.username, self.domain)
        c = Connection(s, user=user, password=self.password)

        if not c.bind():
            Output.error("bug during bind")
            return

        controls = security_descriptor_control(sdflags=0x05)

        entry_generator = c.extend.standard.paged_search(search_base = sbase,
                                                 search_filter = search_filter,
                                                 search_scope = SUBTREE,
                                                 attributes = attributes,
                                                 controls=controls,
                                                 paged_size = 10,
                                                 generator=True)

        #for item in resp:
        #    if isinstance(item, ldapasn1.SearchResultEntry) is not True:
        #        return
        #    attr = self.to_dict(item)

        for item in entry_generator:
            if item['type'] != 'searchResEntry':
                continue

            attr = item['raw_attributes']

            if not 'sAMAccountName' in attr:
                continue

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName'][0].decode()).split(',') if item.split("=",1)[0].lower() == "dc"])
            print(domain)
            username = str(attr['sAMAccountName'][0].decode())
            fullname = str(attr['displayName'][0].decode()) if 'displayName' in attr and len(attr['displayName']) > 0 else ""

            if not 'description' in attr:
                comment = ""
            elif type(attr['description']) == SetOf:
                comment = ",".join([str(s) for s in attr['description']])
            else:
                comment = str(attr['description'])

            #sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical() if 'objectSid' in attr else None
            sid = LDAP_SID(bytes(attr['objectSid'][0])).formatCanonical() if 'objectSid' in attr else None
            if sid:
                rid = int(sid.split('-')[-1])
            else:
                rid = None
            dn = str(attr['distinguishedName'])

            #primaryGID = int(str(attr["primaryGroupID"]))
            primaryGID = int( attr["primaryGroupID"][0].decode() )

            #created_date = datetime.strptime(str(attr['whenCreated']), '%Y%m%d%H%M%S.0Z') 
            created_date = datetime.strptime(str(attr['whenCreated'][0].decode()), '%Y%m%d%H%M%S.0Z') 
            try:
                #last_logon_date = datetime.fromtimestamp(self.getUnixTime(int(str(attr['lastLogon']))))
                last_logon_date = datetime.fromtimestamp(self.getUnixTime(int(str( attr['lastLogon'][0].decode() ))))
            except KeyError:
                last_logon_date = None
            try:
                last_password_change_date = datetime.fromtimestamp(self.getUnixTime(int(str( attr['pwdLastSet'][0].decode() ))))
            except KeyError:
                last_password_change_date = None

            tags = []
            if 'userAccountControl' in attr:
                attr['userAccountControl'] = int( str(attr['userAccountControl'][0].decode() ) )

                #if attr['userAccountControl'] & 0x0200 == 0:
                #    # not a user account
                #    return

                if attr['userAccountControl'] & 2 != 0:
                    tags.append('Account disabled')
                if attr['userAccountControl'] & 0x0020 != 0:
                    tags.append('Password not required')
                if attr['userAccountControl'] & 0x0080 != 0:
                    tags.append('Encrypted text password allowed')
                if attr['userAccountControl'] & 0x0800 != 0:
                    tags.append('Interdomain trust account')
                if attr['userAccountControl'] & 0x1000 != 0:
                    tags.append('Workstation trust account')
                if attr['userAccountControl'] & 0x2000 != 0:
                    tags.append('Server trust account')
                if attr['userAccountControl'] & 0x10000 != 0:
                    tags.append('Password never expire')
                if attr['userAccountControl'] & 0x40000 != 0:
                    tags.append('Smartcard required')
                if attr['userAccountControl'] & 0x80000 != 0:
                    tags.append('Trusted for delegation')
                if attr['userAccountControl'] & 0x100000 != 0:
                    tags.append('Account is sensitive and cannot be delegated')
                if attr['userAccountControl'] & 0x200000 != 0:
                    tags.append('Use DES key only')
                if attr['userAccountControl'] & 0x400000 != 0:
                    tags.append('Do not require pre-auth')
                if attr['userAccountControl'] & 0x1000000 != 0:
                    tags.append('Trusted to auth for delegation')
                if attr['userAccountControl'] & 0x4000000 != 0:
                    tags.append('Partial secrets account')
            else:
                continue

            # Not returned in the Global Catalog
            if 'adminCount' in attr and len(attr['adminCount']) != 0 and int(str(attr['adminCount'][0].decode())) > 0:
                tags.append('adminCount>0')

            groups = [] 
            if 'memberOf' in attr:
                if type(attr['memberOf']) != SetOf:
                    attr['memberOf'] = [attr['memberOf']]

                for memberOf in attr['memberOf']:
                    memberOf = str(memberOf)

                    groupname = memberOf.split(',')[0].split('=')[-1]
                    domain_parts = []
                    for part in memberOf.split(','):
                        subparts = part.split('=')
                        if subparts[0].lower() == "dc":
                            domain_parts.append(subparts[-1])
                    groupdomain = ".".join(domain_parts)

                    groups.append("%s\\%s" % (groupdomain, groupname))

            #aces = parse_sd(bytes(attr['nTSecurityDescriptor']), domain.upper(), 'user', schema_guid_dict)
            aces = parse_sd(attr['nTSecurityDescriptor'][0], domain.upper(), 'user', schema_guid_dict)
            aces = self._resolve_sid_types(aces, "aces")

            if 'msDS-GroupMSAMembership' in attr and len(attr['msDS-GroupMSAMembership']):
                #aces2 = parse_sd(bytes(attr['msDS-GroupMSAMembership']), domain.upper(), 'user', schema_guid_dict)
                aces2 = parse_sd(attr['msDS-GroupMSAMembership'][0], domain.upper(), 'user', schema_guid_dict)
                aces2 = self._resolve_sid_types(aces2, "aces")
                for rule in aces2['aces']:
                    if rule['RightName'] == 'GenericAll':
                        rule['RightName'] = 'GMSAPassword'
                        aces['aces'].append(rule)

            spns = []
            if 'servicePrincipalName' in attr:
                if type(attr['servicePrincipalName']) != SetOf:
                    attr['servicePrincipalName'] = [attr['servicePrincipalName']]

                for spn in attr['servicePrincipalName']:
                    spns.append("%s" % spn)

            callback({
                'domain': domain,
                'username': username,
                'fullname': fullname,
                'comment': comment,
                'created_date': created_date,
                'last_logon': last_logon_date,
                'last_password_change': last_password_change_date,
                'sid': sid,
                'rid': rid,
                'primary_gid': primaryGID,
                'dn': dn,
                'tags': tags,
                'group': groups,
                #'sd': sd,
                'aces': aces,
                'spns': spns,
            })

    def list_admins(self):

        admin_groups = [
            'S-1-5-32-548', # Account Operators
            'S-1-5-32-544', # Administrators
            'S-1-5-32-551', # Backup Operators
            'S-1-5-32-549', # Server Operators
            '%s-1105' % self.domain_sid, # DnsAdmins 
            '%s-512' % self.domain_sid, # Domain Admins 
            '%s-519' % self.domain_sid, # Enterprise Admins
            '%s-520' % self.domain_sid, # Group Policy Creator Owners
        ]

        users_dict = {}

        for admin_group in admin_groups:
            users, groupname = self._get_members_recursive(admin_group, users={})

            for user in users:
                if not user in users_dict:
                    users_dict[user] = {"user": users[user], "groups": []}

                users_dict[user]['groups'].append(groupname)

        for user in users_dict:
            yield {'user': user, 'details': users_dict[user]['user'], 'groups': users_dict[user]['groups']}

    def list_rdp_users(self):

        rdp_groups = [
            'CN=Remote Desktop Users,CN=Builtin,%s' % self.defaultdomainnamingcontext,
        ]

        users_dict = {}

        for rdp_group in rdp_groups:
            users, groupname = self._get_members_recursive(rdp_group, users={})

            for user in users:
                if not user in users_dict:
                    users_dict[user] = {"user": users[user], "groups": []}

                users_dict[user]['groups'].append(groupname)

        for user in users_dict:
            yield {'user': user, 'details': users_dict[user]['user'], 'groups': users_dict[user]['groups']}

    def _get_members_recursive(self, name, users={}):
        if type(name) == int:
            search_filter="(primaryGroupID=%d)" % name
        elif name.startswith('S-'):
            search_filter="(objectsid=%s)" % name
        elif name.startswith('CN='):
            name = name.replace('(', '\\28')
            name = name.replace(')', '\\29')
            search_filter="(distinguishedName=%s)" % name
        else:
            search_filter="(&(objectClass=group)(sAMAccountName=%s))" % name

        sc = ldap.SimplePagedResultsControl(size=10)
        attributes = ['distinguishedName', 'objectClass', 'sAMAccountname', 'displayName', 'description', 'objectSid', 'primaryGroupID', 'whenCreated', 'lastLogon', 'pwdLastSet', 'userAccountControl', 'adminCount', 'memberOf', 'member']
        res = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

        domain = None
        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            attr = self.to_dict(item)

            sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            try:
                name = str(attr['sAMAccountName'])
            except KeyError:
                continue

            if 'user' in str(attr['objectClass']):
                domain_username = "%s\\%s" % (domain, name)

                username = str(attr['sAMAccountName'])
                fullname = str(attr['displayName']) if 'displayName' in attr else ""

                if not 'description' in attr:
                    comment = ""
                elif type(attr['description']) == SetOf:
                    comment = ",".join([str(s) for s in attr['description']])
                else:
                    comment = str(attr['description'])

                sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical() if 'objectSid' in attr else None
                if sid:
                    rid = int(sid.split('-')[-1])
                else:
                    rid = None
                dn = str(attr['distinguishedName'])

                primaryGID = int(str(attr["primaryGroupID"]))

                created_date = datetime.strptime(str(attr['whenCreated']), '%Y%m%d%H%M%S.0Z') 
                try:
                    last_logon_date = datetime.fromtimestamp(self.getUnixTime(int(str(attr['lastLogon']))))
                except KeyError:
                    last_logon_date = None
                try:
                    last_password_change_date = datetime.fromtimestamp(self.getUnixTime(int(str(attr['pwdLastSet']))))
                except KeyError:
                    last_password_change_date = None

                tags = []
                if 'userAccountControl' in attr:
                    attr['userAccountControl'] = int(str(attr['userAccountControl']))

                    if attr['userAccountControl'] & 0x0200 == 0:
                        # not a user account
                        continue

                    if attr['userAccountControl'] & 2 != 0:
                        tags.append('Account disabled')
                    if attr['userAccountControl'] & 0x0020 != 0:
                        tags.append('Password not required')
                    if attr['userAccountControl'] & 0x0080 != 0:
                        tags.append('Encrypted text password allowed')
                    if attr['userAccountControl'] & 0x0800 != 0:
                        tags.append('Interdomain trust account')
                    if attr['userAccountControl'] & 0x1000 != 0:
                        tags.append('Workstation trust account')
                    if attr['userAccountControl'] & 0x2000 != 0:
                        tags.append('Server trust account')
                    if attr['userAccountControl'] & 0x10000 != 0:
                        tags.append('Password never expire')
                    if attr['userAccountControl'] & 0x40000 != 0:
                        tags.append('Smartcard required')
                    if attr['userAccountControl'] & 0x80000 != 0:
                        tags.append('Trusted for delegation')
                    if attr['userAccountControl'] & 0x100000 != 0:
                        tags.append('Account is sensitive and cannot be delegated')
                    if attr['userAccountControl'] & 0x200000 != 0:
                        tags.append('Use DES key only')
                    if attr['userAccountControl'] & 0x400000 != 0:
                        tags.append('Do not require pre-auth')
                    if attr['userAccountControl'] & 0x1000000 != 0:
                        tags.append('Trusted to auth for delegation')
                    if attr['userAccountControl'] & 0x4000000 != 0:
                        tags.append('Partial secrets account')
                else:
                    continue

                if 'adminCount' in attr and int(str(attr['adminCount'])) > 0:
                    tags.append('adminCount>0')

                user_details = {
                    'domain': domain,
                    'username': username,
                    'fullname': fullname,
                    'comment': comment,
                    'created_date': created_date,
                    'last_logon': last_logon_date,
                    'last_password_change': last_password_change_date,
                    'sid': sid,
                    'rid': rid,
                    'primary_gid': primaryGID,
                    'dn': dn,
                    'tags': tags,
                }

                if not domain_username in users:
                    users[domain_username] = user_details
            elif 'group' in str(attr['objectClass']):

                if 'member' in attr:
                    if type(attr['member']) == SetOf:
                        for member in attr['member']:
                            users, _ = self._get_members_recursive(str(member), users=users)
                    else:
                        users, _ = self._get_members_recursive(str(attr['member']), users=users)

                group_gid = int(sid.split('-')[-1])
                users, _ = self._get_members_recursive(group_gid, users=users)

        return users, "%s\\%s" % (domain, name)

    def resolve_dn_to_sid(self, dn_list):
        to_resolve = []
        sid_list = []

        for dn in dn_list:
            if dn in self.dn_to_sid_dict:
                sid_list.append(self.dn_to_sid_dict[dn])
            else:
                to_resolve.append(dn)

        if len(to_resolve) != 0:
            
            search_filter = "(|%s)" % "".join(["(distinguishedName=%s)" % dn.replace('(', '\\28').replace(')', '\\29') for dn in to_resolve])

            sc = ldap.SimplePagedResultsControl(size=10)
            attributes = ['distinguishedName', 'objectSid']
            try:
                res = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter=search_filter, searchControls=[sc], attributes=attributes)
            except LDAPSearchError:
                print('retry')
                res = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

            domain = None
            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                attr = self.to_dict(item)

                sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()
                self.dn_to_sid_dict[attr['distinguishedName']] = sid
                sid_list.append(sid)

        return sid_list


    def list_groups(self, callback):

        schema_guid_dict = self._get_schema_guid_dict(['group', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name'])

        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        attributes = ['distinguishedName', 'sAMAccountname', 'description', 'objectSid', 'primaryGroupID', 'adminCount', 'member', 'nTSecurityDescriptor']
        #self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter='(objectCategory=group)', searchControls=[sc, sc2], perRecordCallback=process, attributes=attributes)
        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter='(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))', searchControls=[sc], attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            if not 'sAMAccountName' in attr:
                return

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            groupname = str(attr['sAMAccountName'])

            if not 'description' in attr:
                comment = ""
            elif type(attr['description']) == SetOf:
                comment = ",".join([str(s) for s in attr['description']])
            else:
                comment = str(attr['description'])


            sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical() if 'objectSid' in attr else None
            if sid:
                rid = int(sid.split('-')[-1])
            else:
                rid = None
            dn = str(attr['distinguishedName'])

            if 'member' in attr:
                if type(attr['member']) == SetOf:
                    for member in attr['member']:
                        members = [str(m) for m in attr['member']]
                else:
                    members = [str(attr['member'])]
            else:
                members = []

            members_sid = self.resolve_dn_to_sid(members)
            members_sid = [process_sid(domain.upper(), sid) for sid in members_sid]
            members_sid = self._resolve_sid_types(members_sid, 'members')

            tags = []

            if 'adminCount' in attr and int(str(attr['adminCount'])) > 0:
                tags.append('adminCount>0')

            aces = parse_sd(bytes(attr['nTSecurityDescriptor']), domain.upper(), 'group', schema_guid_dict)
            aces = self._resolve_sid_types(aces, "aces")

            callback({
                'domain': domain,
                'groupname': groupname,
                'comment': comment,
                'sid': sid,
                'rid': rid,
                'dn': dn,
                'members': members_sid,
                'tags': tags,
                'aces': aces,
            })

    def list_hosts(self, callback):

        schema_guid_dict = self._get_schema_guid_dict(['computer', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name'])

        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        attributes = ['distinguishedName', 'sAMAccountname', 'dNSHostName', 'name', 'operatingSystem', 'description', 'objectSid', 'userAccountControl', 'nTSecurityDescriptor', 'primaryGroupID', 'servicePrincipalName', 'whenCreated', 'lastLogon', 'pwdLastSet']
        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter='(objectCategory=computer)', searchControls=[sc], attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            if not 'sAMAccountName' in attr:
                return

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])

            dns = str(attr["dNSHostName"]) if 'dNSHostName' in attr else ''
            hostname = str(attr['name'])
            os = str(attr['operatingSystem']) if 'operatingSystem' in attr else ''
            comment = str(attr['description']) if 'description' in attr else ""
            sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical() if 'objectSid' in attr else None
            if sid:
                rid = int(sid.split('-')[-1])
            else:
                rid = None
            dn = str(attr['distinguishedName'])
            primaryGID = int(str(attr["primaryGroupID"]))

            created_date = datetime.strptime(str(attr['whenCreated']), '%Y%m%d%H%M%S.0Z') 
            try:
                last_logon_date = datetime.fromtimestamp(self.getUnixTime(int(str(attr['lastLogon']))))
            except KeyError:
                last_logon_date = None
            try:
                last_password_change_date = datetime.fromtimestamp(self.getUnixTime(int(str(attr['pwdLastSet']))))
            except KeyError:
                last_password_change_date = None



            tags = []
            if 'userAccountControl' in attr:
                attr['userAccountControl'] = int(str(attr['userAccountControl']))
                if attr['userAccountControl'] & 2 != 0:
                    tags.append('Account disabled')
                if attr['userAccountControl'] & 0x0020 != 0:
                    tags.append('Password not required')
                if attr['userAccountControl'] & 0x0080 != 0:
                    tags.append('Encrypted text password allowed')
                if attr['userAccountControl'] & 0x0800 != 0:
                    tags.append('Interdomain trust account')
                if attr['userAccountControl'] & 0x1000 != 0:
                    tags.append('Workstation trust account')
                if attr['userAccountControl'] & 0x2000 != 0:
                    tags.append('Server trust account')
                if attr['userAccountControl'] & 0x10000 != 0:
                    tags.append('Password never expire')
                if attr['userAccountControl'] & 0x40000 != 0:
                    tags.append('Smartcard required')
                if attr['userAccountControl'] & 0x80000 != 0:
                    tags.append('Trusted for delegation')
                if attr['userAccountControl'] & 0x100000 != 0:
                    tags.append('Account is sensitive and cannot be delegated')
                if attr['userAccountControl'] & 0x200000 != 0:
                    tags.append('Use DES key only')
                if attr['userAccountControl'] & 0x400000 != 0:
                    tags.append('Do not require pre-auth')
                if attr['userAccountControl'] & 0x1000000 != 0:
                    tags.append('Trusted to auth for delegation')
                if attr['userAccountControl'] & 0x4000000 != 0:
                    tags.append('Partial secrets account')

            aces = parse_sd(bytes(attr['nTSecurityDescriptor']), domain.upper(), 'computer', schema_guid_dict)
            aces = self._resolve_sid_types(aces, "aces")

            spns = []
            if 'servicePrincipalName' in attr:
                if type(attr['servicePrincipalName']) != SetOf:
                    attr['servicePrincipalName'] = [attr['servicePrincipalName']]

                for spn in attr['servicePrincipalName']:
                    spns.append("'%s'" % spn)


            callback({
                'domain': domain,
                'hostname': str(hostname),
                'dns': dns,
                'os': str(os),
                'sid': sid,
                'rid': rid,
                'primary_gid': primaryGID,
                'dn': dn,
                'tags': tags,
                'comment': str(comment),
                'aces': aces,
                'spns': spns,
                'created_date': created_date,
                'last_logon': last_logon_date,
                'last_password_change': last_password_change_date,
            })

    def list_dns(self, callback):

        attributes = ['distinguishedName']
        try:
            resp = self.conn.search(searchBase='CN=MicrosoftDNS,DC=DomainDnsZones,%s' % self.defaultdomainnamingcontext, searchFilter='(objectClass=dnsNode)', attributes=attributes, sizeLimit=0)
        except LDAPSearchError:
            # This DC doesn't have DNS
            pass

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            dn = str(attr["distinguishedName"]).split(",CN=MicrosoftDNS,",1)[0]
            dns_entry = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            if not '.in-addr.arpa' in dns_entry:
                callback(dns_entry)

    def list_trusts(self, callback):

        attributes = ['distinguishedName', 'name', 'trustDirection', 'trustType', 'trustAttributes']
        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter='(objectClass=trustedDomain)', attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            domain = str(attr['name'])

            attr['trustDirection'] = int(str(attr['trustDirection']))
            if attr['trustDirection'] == 0:
                direction = 'Disabled'
            elif attr['trustDirection'] == 1:
                direction = 'Incoming'
            elif attr['trustDirection'] == 2:
                direction = 'Outgoing'
            elif attr['trustDirection'] == 3:
                direction = 'Bidirectional'
            else:
                direction = 'Unknown'

            attr['trustType'] = int(str(attr['trustType']))
            if attr['trustType'] == 1:
                trust_type = 'Windows NT'
            elif attr['trustType'] == 2:
                trust_type = 'Active Directory'
            elif attr['trustType'] == 3:
                trust_type = 'MIT/KRB realm trust'
            else:
                trust_type = 'Unknown'

            tags = []
            attr['trustAttributes'] = int(str(attr['trustAttributes']))
            if attr['trustAttributes'] & 1 != 0:
                tags.append('Non-Transitive')
            if attr['trustAttributes'] & 2 != 0:
                tags.append('Uplevel clients only (Windows 2000 or newer)')
            if attr['trustAttributes'] & 4 != 0:
                tags.append('Quarantined Domain (External)')
            if attr['trustAttributes'] & 8 != 0:
                tags.append('Forest Trust')
            if attr['trustAttributes'] & 16 != 0:
                tags.append('Cross-Organizational Trust (Selective Authentication)')
            if attr['trustAttributes'] & 32 != 0:
                tags.append('Intra-Forest Trust (trust within the forest)')
            if attr['trustAttributes'] & 64 != 0:
                tags.append('Inter-Forest Trust (trust with another forest)')

            callback({
                'domain': domain,
                'direction': direction,
                'type': trust_type,
                'tags': tags,
            })

    def list_casrv(self, callback):

        attributes = ['distinguishedName', 'name', 'dNSHostName']
        resp = self.conn.search(searchBase="CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,%s" % self.defaultdomainnamingcontext, searchFilter="(objectClass=pKIEnrollmentService)", attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            name = str(attr['name'])
            dns = str(attr['dNSHostName'])

            callback({"name": name, "hostname": dns})

    def list_cacerts(self, callback):

        attributes = ['distinguishedName', 'cACertificate']
        resp = self.conn.search(searchBase='CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,%s' % self.defaultdomainnamingcontext, searchFilter='(cn=*)', attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            if type(attr['cACertificate']) != SetOf:
                attr['cACertificate'] = [attr['cACertificate']]
            for cert_bytes in attr['cACertificate']:
                cert_bytes = bytes(cert_bytes)
                cert = x509.load_der_x509_certificate(cert_bytes)

                common_names = [cn.value for cn in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)]

                public_key = cert.public_key()
                if type(public_key) in [RSAPublicKey, _RSAPublicKey]:
                    cert_algo = "RSA %d" % public_key.key_size
                elif type(public_key) in [DSAPublicKey, _DSAPublicKey]:
                    cert_algo = "DSA %d" % public_key.key_size
                elif type(public_key) in [EllipticCurvePublicKey, _EllipticCurvePublicKey]:
                    cert_algo = "EC %d" % public_key.key_size
                else:
                    cert_algo = "Unknown: %s" % type(public_key)

                callback({
                    'algo': cert_algo,
                    'common_names': common_names,
                })

    def list_enrollment_services(self, callback, username=None):
        if username:
            sid_groups = list(self._get_groups_recursive(username).keys())
            sid_groups.append('S-1-1-0')
            sid_groups.append('S-1-5-11')
        else:
            sid_groups = None

        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        attributes = ['distinguishedName', 'name', 'dNSHostName', 'certificateTemplates', 'nTSecurityDescriptor']
        resp = self.conn.search(searchBase='CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,%s' % self.defaultdomainnamingcontext, searchFilter='(objectClass=pKIEnrollmentService)', searchControls=[sc], attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            name = str(attr['name'])
            dns = str(attr['dNSHostName'])
            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])

            if 'certificateTemplates' in attr:
                if not type(attr['certificateTemplates']) == SetOf:
                    attr['certificateTemplates'] = [attr['certificateTemplates']]

                templates = [str(t) for t in attr['certificateTemplates']]
            else:
                templates = []

            output = {
                'name': name,
                'domain': domain,
                'dns': dns, 
                'templates': templates,
            }


            if sid_groups:
                # Check if the user has enrollment rights
                if 'nTSecurityDescriptor' in attr:
                    sd = bytes(attr['nTSecurityDescriptor'])
                else:
                    return

                output['can_enroll'] = False

                for ace in parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext)):
                    if ace['type'] == 'ALLOWED' and 'Certificate-Enrollment' in ace['rights'] and ace['sid'] in sid_groups:
                        output['can_enroll'] = True

            callback(output)

    def list_cert_templates(self, callback):

        # https://www.pkisolutions.com/object-identifiers-oid-in-pki/
        oid_map = {
            "1.3.6.1.4.1.311.76.6.1": "Windows Update",
            "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
            "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
            "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
            "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
            "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Drive",
            "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
            "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
            "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
            "2.23.133.8.3": "Attestation Identity Key Certificate",
            "1.3.6.1.4.1.311.76.3.1": "Windows Store",
            "1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
            "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
            "1.3.6.1.5.2.3.5": "KDC Authentication",
            "1.3.6.1.5.5.7.3.7": "IP security use",
            "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
            "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
            "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
            "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
            "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
            "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
            "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
            "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
            "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generato",
            "1.3.6.1.5.5.7.3.8": "Time Stamping",
            "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
            "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
            "2.23.133.8.1": "Endorsement Key Certificate",
            "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
            "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
            "1.3.6.1.5.5.7.3.1": "Server Authentication",
            "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
            "1.3.6.1.5.5.7.3.4": "Secure Email",
            "1.3.6.1.5.5.7.3.5": "IP security end system",
            "1.3.6.1.4.1.311.10.3.9": "Root List Signe",
            "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
            "1.3.6.1.4.1.311.10.3.19": "Revoked List Signe",
            "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
            "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
            "1.3.6.1.4.1.311.10.3.12": "Document Signing",
            "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
            "1.3.6.1.4.1.311.80.1": "Document Encryption",
            "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
            "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
            "1.3.6.1.4.1.311.21.5": "Private Key Archival",
            "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
            "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
            "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
            "2.23.133.8.2": "Platform Certificate",
            "1.3.6.1.4.1.311.20.1": "CTL Usage",
            "1.3.6.1.5.5.7.3.9": "OCSP Signing",
            "1.3.6.1.5.5.7.3.3": "Code Signing",
            "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
            "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
            "1.3.6.1.4.1.311.76.8.1": "Microsoft Publishe",
            "1.3.6.1.5.5.7.3.2": "Client Authentication",
            "1.3.6.1.5.2.3.4": "PKIINIT Client Authentication",
            "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
            "2.5.29.37.0": "Any Purpose",
            "1.3.6.1.4.1.311.64.1.1": "Server Trust",
            "1.3.6.1.4.1.311.10.3.7": "OEM Windows System Component Verification",
        }

        certificate_name_flag_map = {
            0x1: 'ENROLLEE_SUPPLIES_SUBJECT',
            0x2: 'ADD_EMAIL',
            0x4: 'ADD_OBJ_GUID',
            0x8: 'OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME',
            0x100: 'ADD_DIRECTORY_PATH',
            0x10000: 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME',
            0x400000: 'SUBJECT_ALT_REQUIRE_DOMAIN_DNS',
            0x800000: 'SUBJECT_ALT_REQUIRE_SPN',
            0x1000000: 'SUBJECT_ALT_REQUIRE_DIRECTORY_GUID',
            0x2000000: 'SUBJECT_ALT_REQUIRE_UPN',
            0x4000000: 'SUBJECT_ALT_REQUIRE_EMAIL',
            0x8000000: 'SUBJECT_ALT_REQUIRE_DNS',
            0x10000000: 'SUBJECT_REQUIRE_DNS_AS_CN',
            0x20000000: 'SUBJECT_REQUIRE_EMAIL',
            0x40000000: 'SUBJECT_REQUIRE_COMMON_NAME',
            0x80000000: 'SUBJECT_REQUIRE_DIRECTORY_PATH',
        }

        enrollment_flag_map = {
            0x1: 'INCLUDE_SYMMETRIC_ALGORITHMS',
            0x2: 'PEND_ALL_REQUESTS',
            0x4: 'PUBLISH_TO_KRA_CONTAINER',
            0x8: 'PUBLISH_TO_DS',
            0x10: 'AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE',
            0x20: 'AUTO_ENROLLMENT',
            0x80: 'CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED',
            0x40: 'PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT',
            0x100: 'USER_INTERACTION_REQUIRED',
            0x200: 'ADD_TEMPLATE_NAME',
            0x400: 'REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE',
            0x800: 'ALLOW_ENROLL_ON_BEHALF_OF',
            0x1000: 'ADD_OCSP_NOCHECK',
            0x2000: 'ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL',
            0x4000: 'NOREVOCATIONINFOINISSUEDCERTS',
            0x8000: 'INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS',
            0x10000: 'ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT',
            0x20000: 'ISSUANCE_POLICIES_FROM_REQUEST',
            0x40000: 'SKIP_AUTO_RENEWAL',
        }

        schema_guid_dict = self.generate_guid_dict(all=False)

        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        attributes = ['distinguishedName', 'name', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'nTSecurityDescriptor']
        resp = self.conn.search(searchBase='CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,%s' % self.defaultdomainnamingcontext, searchFilter='(objectClass=pKICertificateTemplate)', searchControls=[sc], attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            name = str(attr['name'])

            eku = []
            if 'pKIExtendedKeyUsage' in attr:
                if type(attr['pKIExtendedKeyUsage']) != SetOf:
                    attr['pKIExtendedKeyUsage'] = [attr['pKIExtendedKeyUsage']]

                for oid in attr['pKIExtendedKeyUsage']:
                    if str(oid) in oid_map:
                        eku.append(oid_map[str(oid)])
                    else:
                        eku.append(str(oid))

            cert_name_flag = []
            if 'msPKI-Certificate-Name-Flag' in attr:
                for val, n in certificate_name_flag_map.items():
                    if val & int(attr['msPKI-Certificate-Name-Flag']) == val:
                        cert_name_flag.append(n)

            enrollment_flag = []
            if 'msPKI-Enrollment-Flag' in attr:
                for val, n in enrollment_flag_map.items():
                    if val & int(attr['msPKI-Enrollment-Flag']) == val:
                        enrollment_flag.append(n)

            authorized_signature_required = False
            if 'msPKI-RA-Signature' in attr:
                if int(attr['msPKI-RA-Signature']) > 0:
                    authorized_signature_required = True

            enrollment_rights = []
            privileges = []
            if 'nTSecurityDescriptor' in attr:
                sd = bytes(attr['nTSecurityDescriptor'])
            else:
                return

            for ace in parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext)):
                ace['target'] = name
                if 'Certificate-Enrollment' in ace['rights']:
                    if ace['type'] == 'ALLOWED':
                        enrollment_rights.append(ace)

                    continue

                if 'guid' in ace and ace['guid'] in schema_guid_dict:
                    ace['parameter'] = schema_guid_dict[ace['guid']]

                privileges.append(ace)

            callback({
                'name': name,
                'eku': eku, 
                'cert_name_flag': cert_name_flag,
                'enrollment_flag': enrollment_flag,
                'enrollment_rights': enrollment_rights,
                'authorized_signature_required': authorized_signature_required,
                'privileges': privileges,
            })


    def check_esc1(self, username, callback):
        sid_groups = list(self._get_groups_recursive(username).keys())
        sid_groups.append('S-1-1-0')
        sid_groups.append('S-1-5-11')

        def process(entry):
            # Exploitable EKU: Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA).
            exploitable_eku_list = [
                "Client Authentication",
                "PKINIT Client Authentication",
                "Smart Card Logon",
                "Any Purpose",
            ]

            found = False
            e_eku = []
            for exploitable_eku in exploitable_eku_list:
                if exploitable_eku in entry['eku']:
                    found = True
                    e_eku.append(exploitable_eku)

            if len(entry['eku']) == 0:
                entry['eku'].append('no EKU')
                found = True
            else:
                entry['eku'] = e_eku

            if not found:
                return

            if not 'ENROLLEE_SUPPLIES_SUBJECT' in entry['cert_name_flag']:
                return

            # Requires Manger approval
            if 'PEND_ALL_REQUESTS' in entry['enrollment_flag']:
                return

            if entry['authorized_signature_required']:
                return

            for ace in entry['enrollment_rights']:
                if ace['sid'] in sid_groups:
                    entry['enrollment_right'] = ace
                    callback(entry)

        self.list_cert_templates(process)

    def check_esc2(self, username, callback):
        sid_groups = list(self._get_groups_recursive(username).keys())
        sid_groups.append('S-1-1-0')
        sid_groups.append('S-1-5-11')

        def process(entry):
            # Exploitable EKU: Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA).
            exploitable_eku_list = [
                "Any Purpose",
            ]

            found = False
            e_eku = []
            for exploitable_eku in exploitable_eku_list:
                if exploitable_eku in entry['eku']:
                    found = True
                    e_eku.append(exploitable_eku)

            if len(entry['eku']) == 0:
                entry['eku'].append('no EKU')
                found = True
            else:
                entry['eku'] = e_eku

            if not found:
                return

            if len(entry['eku']) == 0:
                entry['eku'].append('no EKU')

            # Requires Manger approval
            if 'PEND_ALL_REQUESTS' in entry['enrollment_flag']:
                return

            if entry['authorized_signature_required']:
                return

            for ace in entry['enrollment_rights']:
                if ace['sid'] in sid_groups:
                    entry['enrollment_right'] = ace
                    callback(entry)

        self.list_cert_templates(process)

    def check_esc3(self, username, callback):
        sid_groups = list(self._get_groups_recursive(username).keys())
        sid_groups.append('S-1-1-0')
        sid_groups.append('S-1-5-11')

        def process(entry):
            # Exploitable EKU: Certificate Request Agent OID (1.3.6.1.4.1.311.20.2.1)
            exploitable_eku_list = [
                "Certificate Request Agent",
            ]

            found = False
            e_eku = []
            for exploitable_eku in exploitable_eku_list:
                if exploitable_eku in entry['eku']:
                    found = True
                    e_eku.append(exploitable_eku)

            if not found:
                return

            if len(entry['eku']) == 0:
                entry['eku'].append('no EKU')

            # Requires Manger approval
            if 'PEND_ALL_REQUESTS' in entry['enrollment_flag']:
                return

            if entry['authorized_signature_required']:
                return

            for ace in entry['enrollment_rights']:
                if ace['sid'] in sid_groups:
                    entry['enrollment_right'] = ace
                    callback(entry)

        self.list_cert_templates(process)


    def check_esc4(self, username, callback):
        sid_groups = list(self._get_groups_recursive(username).keys())
        sid_groups.append('S-1-1-0')
        sid_groups.append('S-1-5-11')

        def process(entry):
            for ace in entry['privileges']:
                if ace['sid'] in sid_groups:
                    entry['ace'] = ace
                    callback(entry)

        self.list_cert_templates(process)

    """
    def list_cacerts(self):
        entry_generator = self.conn.extend.standard.paged_search(search_base='CN=NTAuthCertificates,CN=Public Key Services,CN=Services,%s' % self.configurationNamingContext,
                          search_filter="(cn=*)",
                          search_scope=ldap3.SUBTREE,
                          attributes=ldap3.ALL_ATTRIBUTES,
                          get_operational_attributes=True,
                          paged_size = 100,
                          generator=True)

        for obj_info in entry_generator:
                try:
                    attr = obj_info['attributes']
                except KeyError:
                    continue

                for cert_dict in attr['cACertificate']:
                    if type(cert_dict) == dict:
                        if cert_dict['encoding'] == 'base64':
                            b64_cert = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % cert_dict['encoded']
                            cert = x509.load_pem_x509_certificate(b64_cert.encode(), default_backend())

                            common_names = [cn.value for cn in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]

                            public_key = cert.public_key()
                            if type(public_key) in [RSAPublicKey, _RSAPublicKey]:
                                cert_algo = "RSA %d" % public_key.key_size
                            elif type(public_key) in [DSAPublicKey, _DSAPublicKey]:
                                cert_algo = "DSA %d" % public_key.key_size
                            elif type(public_key) in [EllipticCurvePublicKey, _EllipticCurvePublicKey]:
                                cert_algo = "EC %d" % public_key.key_size
                            else:
                                cert_algo = "Unknown: %s" % type(public_key)

                            yield {
                                'algo': cert_algo,
                                'common_names': common_names,
                            }
                        else:
                            yield {
                                'algo': "Unknown cert encoding: %s" % cert_dict['encoding'],
                                'common_names': [],
                            }
                    else:
                        yield {
                            'algo': "Unknown cert, bytes received...",
                            'common_names': [],
                        }
    """
    def list_writable_GPOs(self, smbscan, callback):

        attributes = ['distinguishedName', 'gPCFileSysPath', 'displayName']
        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(objectCategory=groupPolicyContainer)", attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            share_pattern = re.compile("\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)(\\\\.*)")

            attr = self.to_dict(item)

            gpo_path = str(attr["gPCFileSysPath"])
            m = share_pattern.match(gpo_path)

            if m:
                tid = None
                fid = None
                try:
                    tid = smbscan.conn.connectTree(m.group(2))
                    fid = smbscan.conn.openFile(tid, m.group(3) + "\\GPT.INI", desiredAccess=FILE_READ_DATA | FILE_WRITE_DATA)
                    smbscan.conn.closeFile(tid, fid)

                    writable = True
                except impacket.smb.SessionError:
                    writable = False
                except impacket.smbconnection.SessionError:
                    writable = False

                if writable:
                    callback({
                        'name': str(attr['displayName']),
                        'path': str(attr['gPCFileSysPath']),
                    })


    def list_acls(self, username, callback, all=False):

        # First, get all related groups
        sid_groups = list(self._get_groups_recursive(username).keys())
        sid_groups.append('S-1-1-0')
        sid_groups.append('S-1-5-11')

        schema_guid_dict = self.generate_guid_dict(all=all)

        class SdFlags(Sequence):
             # SDFlagsRequestValue ::= SEQUENCE {
             #     Flags    INTEGER
             # }
            componentType = NamedTypes(NamedType('Flags', Integer())
        )

        def get_sd_controls(sdflags=0x04):
            sdcontrol = SdFlags()
            sdcontrol.setComponentByName('Flags', sdflags)
            controls = [build_control('1.2.840.113556.1.4.801', True, sdcontrol)]
            return controls

        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(|(objectClass=user)(objectClass=group)(objectClass=computer))", attributes=['distinguishedName', 'sAMAccountName', 'nTSecurityDescriptor', 'msDS-GroupMSAMembership'], searchControls=[sc], sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            if 'nTSecurityDescriptor' in attr:
                sd = bytes(attr['nTSecurityDescriptor'])
            else:
                return

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            name = str(attr['sAMAccountName'])

            for ace in parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext)):
                if ace['sid'] in sid_groups:
                    ace['target'] = '%s\\%s' % (domain, name)
                    if 'guid' in ace and ace['guid'] in schema_guid_dict:
                        ace['parameter'] = schema_guid_dict[ace['guid']]

                    if all:
                        callback(ace)
                    else:
                        # Only send results with  no guid or specific guids (returned by the function generate_guid_dict)
                        if not 'guid' in ace:
                            callback(ace)
                        if 'parameter' in ace:
                            callback(ace)

            if 'msDS-GroupMSAMembership' in attr:
                sd = bytes(attr['msDS-GroupMSAMembership'])

                for ace in parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext)):
                    ace['target'] = '%s\\%s' % (domain, name)
                    if 'guid' in ace and ace['guid'] in schema_guid_dict:
                        ace['parameter'] = schema_guid_dict[ace['guid']]

                    if all:
                        callback(ace)
                    else:
                        # Only send results with  no guid or specific guids (returned by the function generate_guid_dict)
                        if not 'guid' in ace:
                            callback(ace)
                        if 'parameter' in ace:
                            callback(ace)


        """
        def process(item):
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            if 'nTSecurityDescriptor' in attr:
                sd = bytes(attr['nTSecurityDescriptor'])
            else:
                return

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            name = str(attr['sAMAccountName'])

            for ace in parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext)):
                if ace['sid'] in sid_groups:
                    ace['target'] = '%s\\%s' % (domain, name)
                    if 'guid' in ace and ace['guid'] in schema_guid_dict:
                        ace['parameter'] = schema_guid_dict[ace['guid']]

                    if all:
                        callback(ace)
                    else:
                        # Only send results with  no guid or specific guids (returned by the function generate_guid_dict)
                        if not 'guid' in ace:
                            callback(ace)
                        if 'parameter' in ace:
                            callback(ace)

        sc = ldap.SimplePagedResultsControl(size=10)
        sc2 = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(objectClass=group)", attributes=['distinguishedName', 'sAMAccountName', 'nTSecurityDescriptor'], searchControls=[sc, sc2], perRecordCallback=process )

        def process(item):
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            if 'nTSecurityDescriptor' in attr:
                sd = bytes(attr['nTSecurityDescriptor'])
            else:
                return

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            name = str(attr['sAMAccountName'])

            for ace in parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext)):
                if ace['sid'] in sid_groups:
                    ace['target'] = '%s\\%s' % (domain, name)
                    if 'guid' in ace and ace['guid'] in schema_guid_dict:
                        ace['parameter'] = schema_guid_dict[ace['guid']]

                    if all:
                        callback(ace)
                    else:
                        # Only send results with  no guid or specific guids (returned by the function generate_guid_dict)
                        if not 'guid' in ace:
                            callback(ace)
                        if 'parameter' in ace:
                            callback(ace)

        sc = ldap.SimplePagedResultsControl(size=10)
        sc2 = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(objectClass=computer)", attributes=['distinguishedName', 'sAMAccountName', 'nTSecurityDescriptor'], searchControls=[sc, sc2], perRecordCallback=process )
        """

    def list_constrained_delegations(self, callback):

        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(msDS-AllowedToDelegateTo=*)", attributes=['distinguishedName', 'sAMAccountName', 'msDS-AllowedToDelegateTo'], sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            name = str(attr['sAMAccountName'])
            spn = str(attr['msDS-AllowedToDelegateTo'])

            callback({
                'domain': domain,
                'name': name,
                'spn': spn,
            })



    def list_object_acl(self, object_acl, callback, all=False):
        if object_acl.startswith('S-'):
            search_filter="(objectsid=%s)" % object_acl
        elif object_acl.lower().startswith('cn=') or object_acl.lower().startswith('dc='):
            search_filter="(distinguishedName=%s)" % object_acl
        elif object_acl.startswith('(') and object_acl.endswith(')'):
            search_filter=object_acl
        else:
            search_filter="(|(sAMAccountName=%s)(name=%s))" % (object_acl, object_acl)

        class SdFlags(Sequence):
             # SDFlagsRequestValue ::= SEQUENCE {
             #     Flags    INTEGER
             # }
            componentType = NamedTypes(NamedType('Flags', Integer())
        )

        def get_sd_controls(sdflags=0x04):
            sdcontrol = SdFlags()
            sdcontrol.setComponentByName('Flags', sdflags)
            controls = [build_control('1.2.840.113556.1.4.801', True, sdcontrol)]
            return controls

        schema_guid_dict = self.generate_guid_dict(all=all)

        if "cn=schema,cn=configuration,%s" % self.defaultdomainnamingcontext.lower() in object_acl.lower():
            searchBase = "CN=Schema,CN=Configuration,%s" % self.defaultdomainnamingcontext
        elif "cn=configuration,%s" % self.defaultdomainnamingcontext.lower() in object_acl.lower():
            searchBase = "CN=Configuration,%s" % self.defaultdomainnamingcontext
        elif "dc=domaindnszones,%s" % self.defaultdomainnamingcontext.lower() in object_acl.lower():
            searchBase = "DC=DomainDnsZones,%s" % self.defaultdomainnamingcontext
        elif "dc=forestdnszones,%s" % self.defaultdomainnamingcontext.lower() in object_acl.lower():
            searchBase = "DC=ForestDnsZones,%s" % self.defaultdomainnamingcontext
        else:
            searchBase = self.defaultdomainnamingcontext

        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        resp = self.conn.search(searchBase=searchBase, searchFilter=search_filter, attributes=['distinguishedName', 'sAMAccountName', 'nTSecurityDescriptor', 'name', 'msDS-GroupMSAMembership'], searchControls=[sc], sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])


            if 'sAMAccountName' in attr:
                target = "%s\\%s" % (domain, str(attr['sAMAccountName']))
            else:
                target = str(attr['distinguishedName'])

            if 'nTSecurityDescriptor' in attr:
                sd = bytes(attr['nTSecurityDescriptor'])
                for ace in parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext)):
                    ace['target'] = target
                    if 'guid' in ace and ace['guid'] in schema_guid_dict:
                        ace['parameter'] = schema_guid_dict[ace['guid']]

                    if all:
                        callback(ace)
                    else:
                        # Only send results with  no guid or specific guids (returned by the function generate_guid_dict)
                        if not 'guid' in ace:
                            callback(ace)
                        if 'parameter' in ace:
                            callback(ace)

            if 'msDS-GroupMSAMembership' in attr:
                sd = bytes(attr['msDS-GroupMSAMembership'])

                for ace in parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext)):
                    ace['target'] = target
                    if 'guid' in ace and ace['guid'] in schema_guid_dict:
                        ace['parameter'] = schema_guid_dict[ace['guid']]

                    if all:
                        callback(ace)
                    else:
                        # Only send results with  no guid or specific guids (returned by the function generate_guid_dict)
                        if not 'guid' in ace:
                            callback(ace)
                        if 'parameter' in ace:
                            callback(ace)


    def generate_guid_dict(self, all=False, parameters=['ms-Mcs-AdmPwd', 'msDS-ManagedPassword']):

        guid_dict = {}
        rev_guid_dict = {}

        property_sets = {
            "c7407360-20bf-11d0-a768-00aa006e0529": "General Information",
            "59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "Account Restrictions",
            "4c164200-20c0-11d0-a768-00aa006e0529": "Logon Information",
            "5f202010-79a5-11d0-9020-00c04fc2d4cf": "Group Membership",
            "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Phone and Mail Options",
            "e45795b2-9455-11d1-aebd-0000f80367c1": "Personal Information",
            "77b5b886-944a-11d1-aebd-0000f80367c1": "Web Information",
            "e45795b3-9455-11d1-aebd-0000f80367c1": "Public Information",
            "e48d0154-bcf8-11d1-8702-00c04fb96050": "Remote Access Information",
            "037088f8-0ae1-11d2-b422-00a0c968f939": "Other Domain Parameters",
        }

        if all:
            for guid, prop_set in property_sets.items():
                guid_dict[guid] = {'name': prop_set, 'type': 'PropertySet'}
                rev_guid_dict[prop_set] = {'guid': guid, 'type': 'PropertySet'}

        if all:
            search_filter = "(objectCategory=CN=Attribute-Schema,CN=Schema,CN=Configuration,%s)" % self.defaultdomainnamingcontext
            searchBase = "CN=Schema,CN=Configuration,%s" % self.defaultdomainnamingcontext

            sc = ldap.SimplePagedResultsControl(size=10)
            attributes = ['schemaIDGUID', 'rightsGuid', 'name']
            res = self.conn.search(searchBase=searchBase, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                attr = self.to_dict(item)

                if 'schemaIDGUID' in attr:
                    b = bytes(attr['schemaIDGUID'])
                    guid = b[0:4][::-1].hex() + '-'
                    guid += b[4:6][::-1].hex() + '-'
                    guid += b[6:8][::-1].hex() + '-'
                    guid += b[8:10].hex() + '-'
                    guid += b[10:16].hex()

                    guid_dict[guid] = {'name': str(attr['name']), 'type': 'attribute'}
                    rev_guid_dict[str(attr['name'])] = {'guid': guid, 'type': 'attribute'}

            #search_filter = "(objectCategory=CN=Attribute-Schema,CN=Schema,CN=Configuration,%s)" % self.defaultdomainnamingcontext
            search_filter = "(objectCategory=CN=Control-Access-Right,CN=Schema,CN=Configuration,%s)" % self.defaultdomainnamingcontext
            searchBase = "CN=Configuration,%s" % self.defaultdomainnamingcontext

            sc = ldap.SimplePagedResultsControl(size=10)
            attributes = ['schemaIDGUID', 'rightsGuid', 'name']
            res = self.conn.search(searchBase=searchBase, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                attr = self.to_dict(item)

                if 'rightsGuid' in attr:
                    guid = str(attr['rightsGuid'])
                elif 'schemaIDGUID' in attr:
                    b = bytes(attr['schemaIDGUID'])
                    guid = b[0:4][::-1].hex() + '-'
                    guid += b[4:6][::-1].hex() + '-'
                    guid += b[6:8][::-1].hex() + '-'
                    guid += b[8:10].hex() + '-'
                    guid += b[10:16].hex()


                guid_dict[guid] = {'name': str(attr['name']), 'type': 'AccessControlRight'}
                rev_guid_dict[str(attr['name']).lower()] = guid

        else:
            searchBase = "CN=Schema,CN=Configuration,%s" % self.defaultdomainnamingcontext
            search_filter = "(|%s)" % "".join(["(name=%s)" % s for s in parameters])

            sc = ldap.SimplePagedResultsControl(size=10)
            attributes = ['name', 'schemaIDGUID']
            res = self.conn.search(searchBase=searchBase, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                attr = self.to_dict(item)


                if 'rightsGuid' in attr:
                    guid = str(attr['rightsGuid'])
                elif 'schemaIDGUID' in attr:
                    b = bytes(attr['schemaIDGUID'])
                    guid = b[0:4][::-1].hex() + '-'
                    guid += b[4:6][::-1].hex() + '-'
                    guid += b[6:8][::-1].hex() + '-'
                    guid += b[8:10].hex() + '-'
                    guid += b[10:16].hex()
                else:
                    continue

                guid_dict[guid] = {'name': str(attr['name']), 'type': 'attribute'}
                rev_guid_dict[str(attr['name']).lower()] = guid

        return guid_dict, rev_guid_dict


    # Impacket LDAP does not support binary search
    def resolve_guid(self, guid):
        guid = guid.hex()

        guid_ldap = ''.join(['\\%s' % guid[i:i+2] for i in range(0, len(guid), 2)])

        search_filter = "(schemaIDGUID=%s)" % guid_ldap
        searchBase = "CN=Schema,CN=Configuration,%s" % self.defaultdomainnamingcontext

        sc = ldap.SimplePagedResultsControl(size=10)
        res = self.conn.search(searchBase=searchBase, searchFilter=search_filter, searchControls=[sc], attributes=['name'])

        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            attr = self.to_dict(item)

    def list_user_groups(self, username, callback):

        groups = list(self._get_groups_recursive(username, group_only=True).values())

        for group in groups:
            callback(group)

    def list_group_users(self, groupname, callback):

        users, _ = self._get_members_recursive(groupname, users={})

        for user, details in users.items():
            callback(details)

    def _get_groups_recursive(self, name, groups={}, processed=[], group_only=False):
        if name.startswith('S-'):
            search_filter="(objectsid=%s)" % name
        elif name.startswith('CN='):
            name = name.replace('(', '\\28')
            name = name.replace(')', '\\29')
            search_filter="(distinguishedName=%s)" % name
        else:
            #search_filter="(&(objectClass=user)(sAMAccountName=%s))" % name
            search_filter="(sAMAccountName=%s)" % name

        # First, get all related groups
        new_groups = []

        sc = ldap.SimplePagedResultsControl(size=10)
        attributes = ['objectSid', 'distinguishedName', 'sAMAccountName', 'objectClass', 'primaryGroupID', 'memberOf']
        res = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            attr = self.to_dict(item)

            sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            groupname = str(attr['sAMAccountName'])

            if type(attr['objectClass']) == SetOf:
                object_class = [str(c) for c in attr['objectClass']]
            else:
                object_class = [str(attr['objectClass'])]

            # Processed, add it to list
            if not group_only or group_only and 'group' in object_class:
                if not sid in groups:
                    groups[sid] = "%s\\%s" % (domain, groupname)
                
            if 'primaryGroupID' in attr:
                obj_sid = sid.split('-')
                obj_sid[-1] = str(attr['primaryGroupID'])
                new_groups.append('-'.join(obj_sid))

            if 'memberOf' in attr:
                if type(attr['memberOf']) == SetOf:
                    for memberOf in attr['memberOf']:
                        new_groups.append(str(memberOf))
                else:
                    new_groups.append(str(attr['memberOf']))

        for g in new_groups:
            if not g in processed:
                processed.append(g)

                self._get_groups_recursive(g, groups=groups, processed=processed, group_only=group_only)

        return groups

    # Taken from https://github.com/micahvandeusen/gMSADumper/blob/main/gMSADumper.py
    def dump_gMSA(self, callback):

        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(objectClass=msDS-GroupManagedServiceAccount)", attributes=['distinguishedName', 'sAMAccountName','msDS-ManagedPassword'], sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            username = str(attr['sAMAccountName'])
            try:
                data = bytes(attr['msDS-ManagedPassword'])
                blob = MSDS_MANAGEDPASSWORD_BLOB()
                blob.fromString(data)
                hash = MD4.new ()
                hash.update (blob['CurrentPassword'][:-2])
                passwd = binascii.hexlify(hash.digest()).decode("utf-8")
            except KeyError:
                passwd = 'Error: No msDS-ManagedPassword entry in LDAP'
            except IndexError:
                passwd = 'Error: No msDS-ManagedPassword entry in LDAP'

            callback({
                'domain': domain,
                'username': username,
                'password': passwd,
            })

    # Taken from https://github.com/n00py/LAPSDumper/blob/main/laps.py
    def dump_LAPS(self, callback):
        
        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))", searchControls=[sc], attributes=['distinguishedName', 'dNSHostName', 'sAMAccountName', 'ms-Mcs-AdmPwd', 'Set-AdmPwdReadPasswordPermission'], sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict(item)

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            dns = str(attr['dNSHostName'])
            username = str(attr['sAMAccountName'])
            data = {
                    'domain': domain,
                    'username': username,
                    'dns': dns,
            }

            if 'ms-Mcs-AdmPwd' in attr: 
                data['password'] = str(attr['ms-Mcs-AdmPwd'])

            callback(data)
     
# Taken from https://github.com/micahvandeusen/gMSADumper/blob/main/gMSADumper.py

class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]
