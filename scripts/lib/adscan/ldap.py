#import ldap3
from impacket.ldap import ldap, ldapasn1
import OpenSSL
import re
import binascii
import traceback
import base64
import sys
import time
from uuid import UUID
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
        except ldap3.core.exceptions.LDAPInvalidPortError:
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
    guid_dict = {}
    def resolve_guid(self, guid):
        if guid in self.guid_dict:
            return self.guid_dict[guid]

        # Resolve as a Control access right:
        searchBase = self.configurationnamingcontext
        search_filter = "(RightsGUID=%s)" % guid 

        for attr in self.query_ldap3_generator(searchBase, search_filter, ['name']):
            self.guid_dict[guid] = attr['name']
            return attr['name']

        guid_ldap = ''.join(['\\%02x' % d for d in UUID(guid).bytes_le])
        searchBase = self.schemanamingcontext
        search_filter = "(schemaIDGUID=%s)" % guid_ldap

        for attr in self.query_ldap3_generator(searchBase, search_filter, ['name', 'lDAPDisplayName']):
            self.guid_dict[guid] = attr['lDAPDisplayName']
            return attr['lDAPDisplayName']

        return None

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

    def list_password_policies(self):
        sbase = "%s" % self.defaultdomainnamingcontext
        attributes = ['name', 'description', 'msDS-PasswordComplexityEnabled', 'msDS-MinimumPasswordLength', 'msDS-PasswordHistoryLength', 'msDS-MinimumPasswordAge', 'msDS-MaximumPasswordAge', 'msDS-LockoutThreshold', 'msDS-LockoutDuration', 'msDS-PSOAppliesTo']
        search_filter = '(objectClass=msDS-PasswordSettings)'

        for attr in self.query_generator(sbase, search_filter, attributes):
            applies_to = []
            if 'msDS-PSOAppliesTo' in attr:
                if type(attr['msDS-PSOAppliesTo']) != list:
                    attr['msDS-PSOAppliesTo'] = [attr['msDS-PSOAppliesTo']]

                for item in attr['msDS-PSOAppliesTo']:
                    applies_to.append(item)

            yield {
                'name': str(attr['name']),
                'description': str(attr['description']),
                'complexity': True if str(attr['msDS-PasswordComplexityEnabled']) == 'TRUE' else False,
                'minimum_length': int(attr['msDS-MinimumPasswordLength']),
                'history_length': int(attr['msDS-PasswordHistoryLength']),
                'maximum_age': int(attr['msDS-MaximumPasswordAge']) / -600000000 / 60 / 24, # days
                'minimum_age': int(attr['msDS-MinimumPasswordAge']) / -600000000 / 60 / 24, # days
                'lock_threshold': int(attr['msDS-LockoutThreshold']),
                'lock_duration': int(attr['msDS-LockoutDuration']) / -600000000, # minutes
                'applies_to': applies_to,
            }

    def list_object_acl(self, object_acl):
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

        if object_acl.startswith('S-'):
            search_filter="(objectsid=%s)" % object_acl
        elif object_acl.startswith('CN='):
            object_acl = object_acl.replace('(', '\\28')
            object_acl = object_acl.replace(')', '\\29')
            search_filter="(distinguishedName=%s)" % object_acl
        else:
            search_filter="(sAMAccountName=%s)" % object_acl

        attributes = ['distinguishedName', 'sAMAccountName', 'nTSecurityDescriptor', 'name', 'msDS-GroupMSAMembership', 'objectClass']

        guid_to_name = {}
        ace_list = []

        for attr in self.query_generator(searchBase, search_filter, attributes, query_sd=True):

            domain = self.dn_to_domain(str(attr['distinguishedName']))

            if 'sAMAccountName' in attr:
                target = "%s\\%s" % (domain, str(attr['sAMAccountName']))
            else:
                target = str(attr['distinguishedName'])

            if 'nTSecurityDescriptor' in attr:
                sd = bytes(attr['nTSecurityDescriptor'])
                parsed_ace = parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext))
                for ace in parsed_ace:
                    ace['target'] = target
                    if 'guid' in ace:
                        guid_to_name[ace['guid']] = None

                    ace_list.append(ace)

            if 'msDS-GroupMSAMembership' in attr:
                sd = bytes(attr['msDS-GroupMSAMembership'])

                parsed_ace = parse_accesscontrol(sd, (self.conn, self.defaultdomainnamingcontext))
                for ace in parsed_ace:
                    ace['target'] = target

                    if 'GenericAll' in ace['rights']:
                        ace['rights'] = ['ReadGMSAPassword']
                        ace_list.append(ace)

            # Return only the first result
            break

        for guid in guid_to_name:
            guid_to_name[guid] = self.resolve_guid(guid)

        for ace in ace_list:
            if 'guid' in ace and guid_to_name[ace['guid']] != None:
                ace['parameter'] = guid_to_name[ace['guid']]

        # Send the owner first
        yield ace_list[0]
        for ace in sorted(ace_list[1:], key=lambda d: d['name']):       
            yield ace

