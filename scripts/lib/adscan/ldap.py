#import ldap3
from impacket.ldap import ldap, ldapasn1
import OpenSSL
import re
import binascii
import traceback
import base64
import sys
import time
from datetime import datetime
from utils.structure import Structure
from Cryptodome.Hash import MD4
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
#from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
#from cryptography.hazmat.backends.openssl.dsa import _DSAPublicKey
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
from functools import partial

import ldap3
from ldap3 import Server, Connection, SUBTREE, ALL
from ldap3.protocol.microsoft import security_descriptor_control

from lib.adscan.accesscontrol import extended_rights, parse_accesscontrol, parse_sd, process_sid
from lib.adscan.ou import OU
from lib.adscan.gpo import GPO
from lib.adscan.user import User
from lib.adscan.domain import Domain
from lib.adscan.container import Container
from lib.adscan.group import Group
from lib.adscan.host import Host
from lib.adscan.dns import DNS
from lib.adscan.trust import Trust

from utils.output import Output

class LDAPScan:

    def __init__(self, hostname, timeout, protocol='ldap', python_ldap=False):
        self.hostname = hostname
        #self.port = port
        self.timeout = timeout
        self.protocol = protocol
        self.ssl = protocol.endswith('s')
        # define which lib to use for queries
        self.python_ldap = python_ldap

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
        url = "%s://%s" % (self.protocol, self.hostname)
        return url

    def connect(self, target_domain, domain, username='', password='', ntlm='', doKerberos=False, dc_ip=None):

        # Use LDAP3 to get default naming context and config and schema
        connected = False
        try:
            s = Server('%s://%s' % (self.protocol, self.hostname), get_info=ALL)
            c = Connection(s)
            connected = c.bind()
            
            if not connected:
                return False, None
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return False, None

        self.defaultdomainnamingcontext = c.server.info.other['defaultNamingContext'][0]
        self.configurationnamingcontext = c.server.info.other['configurationNamingContext'][0]
        self.schemanamingcontext = c.server.info.other['schemaNamingContext'][0]

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
            self.target_domain = target_domain
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

            #self.root_namingcontext = self._get_root_namingcontext()

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

    def to_dict_impacket(self, item):
        item_dict = {}
        for attribute in item['attributes']:
            if len(attribute['vals']) == 1:
                value = attribute['vals'][0]
            else:
                value = attribute['vals']

            if type(value) == SetOf:
                v_list = []
                for entry in value:
                    v_list.append(entry)

                item_dict[str(attribute['type'])] = v_list
            else:
                item_dict[str(attribute['type'])] = value

        return item_dict

    def to_dict_ldap3(self, item):
        item_dict = {}
        item = item['raw_attributes']
        for attribute in item:
            if len(item[attribute]) == 0:
                continue

            values = []
            for value in item[attribute]:
                if type(value) == bytes and not attribute in ['objectSid', 'nTSecurityDescriptor', 'msDS-GroupMSAMembership', 'objectGUID', 'cACertificate']:
                    try:
                        value = value.decode()
                    except UnicodeDecodeError:
                        pass
                        #raise Exception("Unable to decode: %s" % attribute)
                values.append(value)

            if len(values) == 1:
                item_dict[attribute] = values[0]
            else:
                item_dict[attribute] = values

        return item_dict

    # =============
    # === Utils ===
    # =============

    def query(self, callback, search_base, search_filter, attributes, query_sd=False, page_size=1000, scope=None):

        for result in self.query_generator(search_base, search_filter, attributes, query_sd=query_sd, page_size=page_size, scope=scope):
            callback(result)

    def query_impacket_generator(self, search_base, search_filter, attributes, query_sd=False, page_size=1000, scope=None):
        search_controls = [ldap.SimplePagedResultsControl(criticality=True, size=page_size)]
        if query_sd:
            search_controls.append(ldapasn1.SDFlagsControl(criticality=True, flags=0x7))

        if search_base == None:
            search_base = "%s" % self.defaultdomainnamingcontext

        if scope != None:
            scope = Scope(scope)

        for item in self.conn.search(searchBase=search_base, searchFilter=search_filter, searchControls=search_controls, attributes=attributes, scope=scope):
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            yield self.to_dict_impacket(item)

    def query_ldap3_generator(self, search_base, search_filter, attributes, query_sd=False, page_size=1000, scope=None):
        if self.protocol == "ldap":
            port = 389
            use_ssl = False
        elif self.protocol == "ldaps":
            port = 636
            use_ssl = True
        elif self.protocol == "gc":
            port = 3268
            use_ssl = False
        else:
            raise Exception("Unknown protocol")

        s = Server(self.hostname, port=port, use_ssl=use_ssl, get_info=ALL)  
        if not self.do_kerberos:
            user = "%s\\%s" % (self.domain, self.username)
            if self.nt_hash != '':
                ntlm_hash = "%s:%s" % (self.lm_hash, self.nt_hash)
                c = Connection(s, user=user, password=ntlm_hash.upper(), authentication=ldap3.NTLM)
            else:
                c = Connection(s, user=user, password=self.password, authentication=ldap3.NTLM)
        else:
            user = "%s@%s" % (self.username, self.domain)
            c = Connection(s, user=user, authentication = ldap3.SASL, sasl_mechanism=ldap3.KERBEROS)

        if not c.bind():
            reason = c.result['message'] 
            raise Exception("bug during bind: %s" % reason)

        search_controls = None
        if query_sd:
            search_controls = security_descriptor_control(sdflags=0x05)

        if scope == None:
            scope = SUBTREE
        else:
            raise NotImplementedError('scope not implemented')

        entry_generator = c.extend.standard.paged_search(search_base = search_base,
                                             search_filter = search_filter,
                                             search_scope = scope,
                                             attributes = attributes,
                                             controls = search_controls,
                                             paged_size = page_size,
                                             generator=True)

        for item in entry_generator:
            if item['type'] != 'searchResEntry':
                continue

            yield self.to_dict_ldap3(item)

    def query_generator(self, search_base, search_filter, attributes, query_sd=False, page_size=1000, scope=None):
        if not self.python_ldap:
            # use impacket ldap
            for item in self.query_impacket_generator(search_base, search_filter, attributes, query_sd=query_sd, page_size=page_size, scope=scope):
                yield item
        else:
            # use ldap3
            for item in self.query_ldap3_generator(search_base, search_filter, attributes, query_sd=query_sd, page_size=page_size, scope=scope):
                yield item

    def getUnixTime(self, t):
        t -= 116444736000000000
        t /= 10000000
        return t

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

            attr = self.to_dict_impacket(item)

            if 'objectSid' in attr:
                return_sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()
                break

        return return_sid

    def _resolve_sid_to_name(self, domain, sid):
        # Child object
        search_filter = "(objectSid=%s)" % sid
        search_base = ",".join(["DC=%s" % dc for dc in domain.split('.')])

        sc = ldap.SimplePagedResultsControl(size=10)
        attributes = ['distinguishedName', 'sAMAccountName']
        res = self.conn.search(searchBase=search_base, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

        name = sid

        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            attr = self.to_dict_impacket(item)

            if 'sAMAccountName' in attr:
                name = str(attr['sAMAccountName'])
                break

        return name


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

            attr = self.to_dict_impacket(item)

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

                attr = self.to_dict_impacket(item)

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
            retry = 0
            while True:
                try:
                    res = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

                    break
                except OpenSSL.SSL.SysCallError as e:
                    time.sleep(1)
                    if retry < 3:
                        Output.error("Error after 3 retries: %s" % str(e))
                        Output.error(search_filter)
                        res = []
                        break
                except Exception as e:
                    time.sleep(1)
                    if retry < 3:
                        Output.error("Error after 3 retries: %s" % str(e))
                        Output.error(search_filter)
                        res = []
                        break

                    retry += 1


            domain = None
            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                attr = self.to_dict_impacket(item)

                if not 'objectSid' in attr:
                    continue

                sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()

                if type(attr['objectClass']) in [SetOf, list]:
                    class_list = [str(c) for c in attr['objectClass']]
                else:
                    class_list = [str(attr['objectClass'])]

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
            search_filter = "(objectCategory=CN=Attribute-Schema,%s)" % self.schemanamingcontext
            searchBase = self.schemanamingcontext

            sc = ldap.SimplePagedResultsControl(size=10)
            attributes = ['schemaIDGUID', 'rightsGuid', 'name']
            res = self.conn.search(searchBase=searchBase, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                attr = self.to_dict_impacket(item)

                if 'schemaIDGUID' in attr:
                    b = bytes(attr['schemaIDGUID'])
                    guid = b[0:4][::-1].hex() + '-'
                    guid += b[4:6][::-1].hex() + '-'
                    guid += b[6:8][::-1].hex() + '-'
                    guid += b[8:10].hex() + '-'
                    guid += b[10:16].hex()

                    guid_dict[guid] = {'name': str(attr['name']), 'type': 'attribute'}
                    rev_guid_dict[str(attr['name'])] = {'guid': guid, 'type': 'attribute'}

            #search_filter = "(objectCategory=CN=Attribute-Schema,CN=Schema,CN=Configuration,%s)" % self.root_namingcontext
            search_filter = "(objectCategory=CN=Control-Access-Right,%s)" % self.schemanamingcontext
            searchBase = self.configurationnamingcontext

            sc = ldap.SimplePagedResultsControl(size=10)
            attributes = ['schemaIDGUID', 'rightsGuid', 'name']
            res = self.conn.search(searchBase=searchBase, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                attr = self.to_dict_impacket(item)

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
            searchBase = self.schemanamingcontext
            search_filter = "(|%s)" % "".join(["(name=%s)" % s for s in parameters])

            sc = ldap.SimplePagedResultsControl(size=10)
            attributes = ['name', 'schemaIDGUID']
            res = self.conn.search(searchBase=searchBase, searchFilter=search_filter, searchControls=[sc], attributes=attributes)

            for item in res:
                if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                    continue

                attr = self.to_dict_impacket(item)

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
        searchBase = self.schemanamingcontext

        sc = ldap.SimplePagedResultsControl(size=10)
        res = self.conn.search(searchBase=searchBase, searchFilter=search_filter, searchControls=[sc], attributes=['name'])

        for item in res:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            attr = self.to_dict_impacket(item)



    """
    def _get_members_recursive(self, name, users={}, processed_groups=[]):
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

        group_info = {'domain': None, 'name': None}
        def process(attr, users={}, processed_groups=[], group_info={}):

            sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            try:
                name = str(attr['sAMAccountName'])
            except KeyError:
                return
            
            group_info['domain'] = domain
            group_info['name'] = name

            if type(attr['objectClass']) in [SetOf, list]:
                object_class = [str(c) for c in attr['objectClass']]
            else:
                object_class = [str(attr['objectClass'])]

            if 'user' in object_class:
                domain_username = "%s\\%s" % (domain, name)

                username = str(attr['sAMAccountName'])
                fullname = str(attr['displayName']) if 'displayName' in attr else ""

                if not 'description' in attr:
                    comment = ""
                elif type(attr['description']) == list:
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

                try:
                    created_date = datetime.strptime(str(attr['whenCreated']), '%Y%m%d%H%M%S.0Z') 
                except KeyError:
                    created_date = None
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

                    #if attr['userAccountControl'] & 0x0200 == 0:
                    #    # not a user account
                    #    continue

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
                    pass

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
            elif 'group' in object_class:

                sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()

                if not sid in processed_groups:
                    processed_groups.append(sid)

                    if 'member' in attr:
                        if type(attr['member']) == list:
                            for member in attr['member']:
                                users, _ = self._get_members_recursive(str(member), users=users, processed_groups=processed_groups)
                        else:
                            users, _ = self._get_members_recursive(str(attr['member']), users=users, processed_groups=processed_groups)

                    group_gid = int(sid.split('-')[-1])
                    users, _ = self._get_members_recursive(group_gid, users=users)

        sbase = self.defaultdomainnamingcontext
        attributes = ['distinguishedName', 'objectClass', 'sAMAccountname', 'displayName', 'description', 'objectSid', 'primaryGroupID', 'whenCreated', 'lastLogon', 'pwdLastSet', 'userAccountControl', 'adminCount', 'memberOf', 'member']

        self.query(partial(process, users=users, processed_groups=processed_groups, group_info=group_info), sbase, search_filter, attributes, query_sd=False)

        return users, "%s\\%s" % (group_info['domain'], group_info['name'])

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

            attr = self.to_dict_impacket(item)

            sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            groupname = str(attr['sAMAccountName'])

            if type(attr['objectClass']) in [SetOf, list]:
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
                if type(attr['memberOf']) == list:
                    for memberOf in attr['memberOf']:
                        new_groups.append(str(memberOf))
                else:
                    new_groups.append(str(attr['memberOf']))

        for g in new_groups:
            if not g in processed:
                processed.append(g)

                self._get_groups_recursive(g, groups=groups, processed=processed, group_only=group_only)

        return groups
    """

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

                attr = self.to_dict_impacket(item)

                if 'objectSid' in attr and 'distinguishedName' in attr:
                    sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()
                    self.dn_to_sid_dict[attr['distinguishedName']] = sid
                    sid_list.append(sid)

        return sid_list

    def dn_to_domain(self, dn):
        return ".".join([item.split("=", 1)[-1] for item in dn.split(',') if item.split("=",1)[0].lower() == "dc"])

    def parse_guid(self, guid_bytes):
        guid = guid_bytes[0:4][::-1].hex() + '-'
        guid += guid_bytes[4:6][::-1].hex() + '-'
        guid += guid_bytes[6:8][::-1].hex() + '-'
        guid += guid_bytes[8:10].hex() + '-'
        guid += guid_bytes[10:16].hex()

        return guid


    # ====================================
    # === Active Directory Enumeration ===
    # ====================================

    def list_domains(self, smbscan, callback):
        for domain in Domain.list_domains(self, smbscan):
            callback(domain.to_json())

    def list_containers(self, domain, callback):
        for container in Container.list_containers(self):
            if container.domain.lower() != domain.lower():
                return
            callback(container.to_json())

    def list_ous(self, smbscan, domain, domain_sid, callback):
        for ou in OU.list_ous(self, smbscan):
            if ou.domain.lower() != domain.lower():
                continue
            callback(ou.to_json())

    def list_gpos(self, callback):
        for gpo in GPO.list_gpos(self):
            callback(gpo.to_json())

    def list_users(self, callback):
        for user in User.list_users(self):
            callback(user.to_json())

    def list_groups(self, callback):
        for group in Group.list_groups(self):
            callback(group.to_json())

    def list_hosts(self, callback):
        for host in Host.list_hosts(self):
            callback(host.to_json())

    def list_dns(self, callback):
        for dns in DNS.list_dns(self):
            callback(dns.to_json()['dns'])

    def list_trusts(self, callback):
        for trust in Trust.list_trust(self):
            callback(trust.to_json())

    def list_casrv(self, callback):

        def process(attr):
            name = str(attr['name'])
            dns = str(attr['dNSHostName'])

            callback({"name": name, "hostname": dns})

        sbase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,%s" % self.configurationnamingcontext
        search_filter="(objectClass=pKIEnrollmentService)"
        attributes = ['distinguishedName', 'name', 'dNSHostName']
        self.query(process, sbase, search_filter, attributes, query_sd=False)

    def list_cacerts(self, callback):


        def process(attr):

            if type(attr['cACertificate']) != list:
                attr['cACertificate'] = [attr['cACertificate']]
            for cert_bytes in attr['cACertificate']:
                cert_bytes = bytes(cert_bytes)
                cert = x509.load_der_x509_certificate(cert_bytes)

                common_names = [cn.value for cn in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)]

                public_key = cert.public_key()
                if type(public_key) in [RSAPublicKey, _RSAPublicKey]:
                    cert_algo = "RSA %d" % public_key.key_size
                    #elif type(public_key) in [DSAPublicKey, _DSAPublicKey]:
                    #cert_algo = "DSA %d" % public_key.key_size
                elif type(public_key) in [EllipticCurvePublicKey, _EllipticCurvePublicKey]:
                    cert_algo = "EC %d" % public_key.key_size
                else:
                    cert_algo = "Unknown: %s" % type(public_key)

                callback({
                    'algo': cert_algo,
                    'common_names': common_names,
                })

        sbase = 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,%s' % self.configurationnamingcontext
        search_filter = '(cn=*)'
        attributes = ['distinguishedName', 'cACertificate']
        self.query(process, sbase, search_filter, attributes, query_sd=False)

    def list_enrollment_services(self, callback, username=None):
        if username:
            sid_groups = list(self._get_groups_recursive(username).keys())
            sid_groups.append('S-1-1-0')
            sid_groups.append('S-1-5-11')
        else:
            sid_groups = None

        def process(attr):

            name = str(attr['name'])
            dns = str(attr['dNSHostName'])
            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])

            if 'certificateTemplates' in attr:
                if not type(attr['certificateTemplates']) == list:
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

        sbase = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,%s' % self.configurationnamingcontext
        search_filter = '(objectClass=pKIEnrollmentService)'
        attributes = ['distinguishedName', 'name', 'dNSHostName', 'certificateTemplates', 'nTSecurityDescriptor']
        self.query(process, sbase, search_filter, attributes, query_sd=False)

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

        def process(attr):

            name = str(attr['name'])

            eku = []
            if 'pKIExtendedKeyUsage' in attr:
                if type(attr['pKIExtendedKeyUsage']) != list:
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

        sbase = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,%s' % self.configurationnamingcontext
        search_filter = '(objectClass=pKICertificateTemplate)'
        attributes = ['distinguishedName', 'name', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'nTSecurityDescriptor']
        self.query(process, sbase, search_filter, attributes, query_sd=False)

    def list_writable_GPOs(self, smbscan, callback):

        attributes = ['distinguishedName', 'gPCFileSysPath', 'displayName']
        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(objectCategory=groupPolicyContainer)", attributes=attributes, sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            share_pattern = re.compile("\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)(\\\\.*)")

            attr = self.to_dict_impacket(item)

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



    def list_admins(self):

        admin_groups = [
            'S-1-5-32-548', # Account Operators
            'S-1-5-32-544', # Administrators
            'S-1-5-32-551', # Backup Operators
            'S-1-5-32-549', # Server Operators
            'DnsAdmins', # DnsAdmins 
            '%s-512' % self.domain_sid, # Domain Admins 
            '%s-519' % self.domain_sid, # Enterprise Admins
            '%s-520' % self.domain_sid, # Group Policy Creator Owners
            '%s-525' % self.domain_sid, # Protected Users
        ]

        users_dict = {}

        for admin_group in admin_groups:
            users, groupname = Group.get_members_recursive(self, admin_group, users={})

            for user in users:
                if not user in users_dict:
                    users_dict[user] = {"user": users[user].to_json(), "groups": []}

                users_dict[user]['groups'].append(groupname)

        for user in users_dict:
            yield {'user': user, 'details': users_dict[user]['user'], 'groups': users_dict[user]['groups']}

    def list_rdp_users(self):

        rdp_groups = [
            'CN=Remote Desktop Users,CN=Builtin,%s' % self.defaultdomainnamingcontext,
        ]

        users_dict = {}

        for rdp_group in rdp_groups:
            users, groupname = Group.get_members_recursive(self, rdp_group, users={})

            for user in users:
                if not user in users_dict:
                    users_dict[user] = {"user": users[user].to_json(), "groups": []}

                users_dict[user]['groups'].append(groupname)

        for user in users_dict:
            yield {'user': user, 'details': users_dict[user]['user'], 'groups': users_dict[user]['groups']}

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

            attr = self.to_dict_impacket(item)

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

    def list_constrained_delegations(self, callback):

        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(msDS-AllowedToDelegateTo=*)", attributes=['distinguishedName', 'sAMAccountName', 'msDS-AllowedToDelegateTo'], sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict_impacket(item)

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

        #schema_guid_dict = self.generate_guid_dict(all=all)

        if self.schemanamingcontext.lower() in object_acl.lower():
            searchBase = self.schemanamingcontext
        elif self.configurationnamingcontext.lower() in object_acl.lower():
            searchBase = self.configurationnamingcontext
        elif "dc=domaindnszones,%s" % self.defaultdomainnamingcontext.lower() in object_acl.lower():
            searchBase = "DC=DomainDnsZones,%s" % self.defaultdomainnamingcontext
        elif "dc=forestdnszones,%s" % self.defaultdomainnamingcontext.lower() in object_acl.lower():
            searchBase = "DC=ForestDnsZones,%s" % self.defaultdomainnamingcontext
        else:
            searchBase = self.defaultdomainnamingcontext

        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        resp = self.conn.search(searchBase=searchBase, searchFilter=search_filter, attributes=['distinguishedName', 'sAMAccountName', 'nTSecurityDescriptor', 'name', 'msDS-GroupMSAMembership', 'objectClass'], searchControls=[sc], sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict_impacket(item)

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])


            if 'sAMAccountName' in attr:
                target = "%s\\%s" % (domain, str(attr['sAMAccountName']))
            else:
                target = str(attr['distinguishedName'])

            if 'nTSecurityDescriptor' in attr:
                sd = bytes(attr['nTSecurityDescriptor'])
                parsed_ace = parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext))
                for ace in parsed_ace:
                    ace['target'] = target
                    if 'guid' in ace and ace['guid'] in extended_rights:
                        ace['parameter'] = extended_rights[ace['guid']]

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

                parsed_ace = parse_sd(sd, domain, object_type, schema_guid_dict)
                for ace in parsed_ace:
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


    def list_user_groups(self, username, callback):

        groups = list(User.get_groups_recursive(self, username, group_only=True).values())

        for group in groups:
            callback(group.to_json())

    def list_group_users(self, groupname, callback):

        users, _ = Group.get_members_recursive(self, groupname, users={})

        for user, details in users.items():
            callback(details.to_json())

    # Taken from https://github.com/micahvandeusen/gMSADumper/blob/main/gMSADumper.py
    def dump_gMSA(self, callback):

        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(objectClass=msDS-GroupManagedServiceAccount)", attributes=['distinguishedName', 'sAMAccountName','msDS-ManagedPassword'], sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict_impacket(item)

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

    def dump_sMSA(self, callback):

        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(objectClass=msDS-ManagedServiceAccount)", attributes=['distinguishedName', 'sAMAccountName','msDS-HostServiceAccountBL'], sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict_impacket(item)

            domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            username = str(attr['sAMAccountName'])
            if 'msDS-HostServiceAccountBL' in attr:
                target_host = str(attr['msDS-HostServiceAccountBL'])
            else:
                target_host = "Not linked to a host"

            callback({
                'domain': domain,
                'username': username,
                'target_host': target_host,
            })



    # Taken from https://github.com/n00py/LAPSDumper/blob/main/laps.py
    def dump_LAPS(self, callback):
        
        sc = ldapasn1.SDFlagsControl(criticality=True, flags=0x7)
        resp = self.conn.search(searchBase=self.defaultdomainnamingcontext, searchFilter="(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))", searchControls=[sc], attributes=['distinguishedName', 'dNSHostName', 'sAMAccountName', 'ms-Mcs-AdmPwd', 'Set-AdmPwdReadPasswordPermission'], sizeLimit=0)

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                return

            attr = self.to_dict_impacket(item)

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
