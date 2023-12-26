import ldap3
import json
import datetime
import binascii
import os
from enum import Enum
from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin, bin_to_string
from ldap3 import Server, Connection, SUBTREE, ALL
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control

from utils.utils import open

# Simple permissions enum
# Simple permissions are combinaisons of extended permissions
# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc783530(v=ws.10)?redirectedfrom=MSDN
class SIMPLE_PERMISSIONS(Enum):
    FullControl = 0xf01ff
    Modify = 0x0301bf
    ReadAndExecute = 0x0200a9
    ReadAndWrite = 0x02019f
    Read = 0x20094
    Write = 0x200bc

class ADEdit:

    def __init__(self, ldap):
        self.protocol = ldap.protocol
        self.target_domain = ldap.target_domain
        self.domain = ldap.domain
        self.hostname = ldap.hostname
        self.username = ldap.username
        self.password = ldap.password
        self.nt_hash = ldap.nt_hash
        self.lm_hash = ldap.lm_hash
        self.do_kerberos = ldap.do_kerberos
        self.root = ldap.defaultdomainnamingcontext
        self.schema = ldap.schemanamingcontext
        self.configuration = ldap.configurationnamingcontext

    def connect(self):

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
            raise exception("unknown protocol")

        s = Server(self.hostname, port=port, use_ssl=use_ssl, get_info=ALL)  # define an unsecure ldap server, requesting info on dse and schema
        if not self.do_kerberos:
            user = "%s\\%s" % (self.domain, self.username)
            if self.nt_hash != '':
                ntlm_hash = "%s:%s" % (self.lm_hash, self.nt_hash)
                self.session = Connection(s, user=user, password=ntlm_hash.upper(), authentication=ldap3.NTLM)
            else:
                self.session = Connection(s, user=user, password=self.password, authentication=ldap3.NTLM)
        else:
            user = "%s@%s" % (self.username, self.domain)
            self.session = Connection(s, user=user, authentication = ldap3.SASL, sasl_mechanism=ldap3.KERBEROS)

        if not self.session.bind():
            reason = self.session.result['message'] 
            return reason

        return True

    def add_user_to_group(self, group_dn, user_dn):
        return self.modify_add(group_dn, 'member', user_dn)

    def remove_user_from_group(self, group_dn, user_dn):
        return self.modify_delete(group_dn, 'member', user_dn)

    # Code taken from: https://github.com/ShutdownRepo/impacket/blob/dacledit/examples/dacledit.py

    def backup_acl(self, object_dn):
        # Get the current acl and backup it
        controls = security_descriptor_control(sdflags=0x04)

        self.session.search(self.root, '(distinguishedName=%s)' % object_dn, attributes=['nTSecurityDescriptor'], controls=controls)

        try:
            entry = self.session.entries[0]

            raw_security_descriptor = entry['nTSecurityDescriptor'].raw_values[0]
            security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_security_descriptor)

            backup = {}
            backup["sd"] = binascii.hexlify(raw_security_descriptor).decode('utf-8')
            backup["dn"] = object_dn

            filename = 'acl-%s-%s.acl' % (object_dn.split(',')[0].split('=')[-1], datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))

            if os.path.exists(filename):
                return "File already exists, refusing to overwrite it", None, None

            f = open(filename, 'w')
            f.write(json.dumps(backup))
            f.close()
        except IndexError:
            return "Unable to find the principal with DN: %s" % object_dn, None, None 

        return True, filename, security_descriptor

    def set_owner(self, principal_dn, target_dn, security_descriptor):
    
        # Query the SID

        self.session.search(self.root, '(distinguishedName=%s)' % principal_dn, attributes=['objectSid'])

        try:
            entry = self.session.entries[0]

            principal_SID = format_sid(entry['objectSid'].raw_values[0])

            _new_owner_SID = ldaptypes.LDAP_SID()
            _new_owner_SID.fromCanonical(principal_SID)

            security_descriptor['OwnerSid'] = _new_owner_SID

            return self.modify_replace(target_dn, 'nTSecurityDescriptor', security_descriptor.getData(), controls = security_descriptor_control(sdflags=0x01))

        except IndexError:
            return "Unable to find the principal with DN: %s" % principal_dn, None, None 


    def add_ace(self, principal_dn, right, target_dn, security_descriptor):
    
        # Query the SID

        self.session.search(self.root, '(distinguishedName=%s)' % principal_dn, attributes=['objectSid'])

        try:
            entry = self.session.entries[0]

            principal_SID = format_sid(entry['objectSid'].raw_values[0])

            if right == "FullControl":
                security_descriptor['Dacl'].aces.append(self.create_ace(SIMPLE_PERMISSIONS.FullControl.value, principal_SID, "allowed"))
            else:
                rights_dict = self.generate_rights_dict()
            
                if right == "DCSync":
                    ace_rights = ["DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"]
                elif right == "WriteMembers":
                    ace_rights = ["Self-Membership"]
                elif right == "ResetPassword":
                    ace_rights = ["User-Force-Change-Password"]
                else:
                    ace_rights = right.split(',')

                for r in ace_rights:
                    guid = rights_dict[r]

                    security_descriptor['Dacl'].aces.append(self.create_object_ace(guid, principal_SID, "allowed"))

            return self.modify_replace(target_dn, 'nTSecurityDescriptor', security_descriptor.getData(), controls = security_descriptor_control(sdflags=0x04))

        except IndexError:
            return "Unable to find the principal with DN: %s" % principal_dn, None, None 

    def restore_acl(self, file):

        f = open(file, 'r')
        data = f.read()
        f.close()

        json_data = json.loads(data)

        object_dn = json_data['dn']

        security_descriptor_raw = binascii.unhexlify(json_data['sd'])

        return self.modify_replace(object_dn, 'nTSecurityDescriptor', security_descriptor_raw, controls = security_descriptor_control(sdflags=0x04))

    def add_computer(self, computer_name, computer_password):

        if not computer_name.endswith('$'):
            computer_name = computer_name + '$'

        # hostname = computer_name without the trailing $
        hostname = computer_name[:-1]

        computer_group = 'CN=Computers,' + ",".join(["DC=%s" % part for part in self.target_domain.split('.')])
        computer_dn = ('CN=%s,%s' % (hostname, computer_group))

        # Default computer SPNs
        spns = [
            'HOST/%s' % hostname,
            'HOST/%s.%s' % (hostname, self.target_domain),
            'RestrictedKrbHost/%s' % hostname,
            'RestrictedKrbHost/%s.%s' % (hostname, self.target_domain),
        ]
        ucd = {
            'dnsHostName': '%s.%s' % (hostname, self.target_domain),
            'userAccountControl': 0x1000,
            'servicePrincipalName': spns,
            'sAMAccountName': computer_name,
            'unicodePwd': ('"%s"' % computer_password).encode('utf-16-le')
        }

        self.session.add(computer_dn, ['top','person','organizationalPerson','user','computer'], ucd)

        if self.session.result['result'] == 0:
            return True, computer_dn
        else:
            return self.session.result['description'], computer_dn

    def del_object(self, object_dn):
        self.session.delete(object_dn)

        if self.session.result['result'] == 0:
            return True
        else:
            return self.session.result['description']

    def set_password(self, object_dn, password):
        return self.modify_replace(object_dn, 'unicodePwd', '"{}"'.format(password).encode('utf-16-le'))



    # Builds a standard ACE for a specified access mask (rights) and a specified SID (the principal who obtains the right)
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb
    #   - access_mask : the allowed access mask
    #   - sid : the principal's SID
    #   - ace_type : the ACE type (allowed or denied)
    def create_ace(self, access_mask, sid, ace_type, inheritance=False):
        nace = ldaptypes.ACE()
        if ace_type == "allowed":
            nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        else:
            nace['AceType'] = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_DENIED_ACE()
        if inheritance:
            nace['AceFlags'] = ldaptypes.ACE.OBJECT_INHERIT_ACE + ldaptypes.ACE.CONTAINER_INHERIT_ACE
        else:
            nace['AceFlags'] = 0x00
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = access_mask
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        nace['Ace'] = acedata
        return nace

    # Builds an object-specific for a specified ObjectType (an extended right, a property, etc, to add) for a specified SID (the principal who obtains the right)
    # The Mask is "ADS_RIGHT_DS_CONTROL_ACCESS" (the ObjectType GUID will identify an extended access right)
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
    #   - privguid : the ObjectType (an Extended Right here)
    #   - sid : the principal's SID
    #   - ace_type : the ACE type (allowed or denied)
    def create_object_ace(self, privguid, sid, ace_type, inheritance=False):
        nace = ldaptypes.ACE()
        if ace_type == "allowed":
            nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        else:
            nace['AceType'] = ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_DENIED_OBJECT_ACE()
        if inheritance:
            nace['AceFlags'] = ldaptypes.ACE.OBJECT_INHERIT_ACE + ldaptypes.ACE.CONTAINER_INHERIT_ACE
        else:
            nace['AceFlags'] = 0x00
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        # WriteMembers not an extended right, we need read and write mask on the attribute (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe)
        if privguid == 'bf9679c0-0de6-11d0-a285-00aa003049e2': # WriteMembers
            acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP + ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
        # Other rights in this script are extended rights and need the DS_CONTROL_ACCESS mask
        else:
            acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
        acedata['ObjectType'] = string_to_bin(privguid)
        acedata['InheritedObjectType'] = b''
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        assert sid == acedata['Sid'].formatCanonical()
        # This ACE flag verifes if the ObjectType is valid
        acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        nace['Ace'] = acedata
        return nace


    def modify_add(self, object_dn, key, value, controls=None):
        try:
            self.session.modify(object_dn, {key: [( ldap3.MODIFY_ADD, [value] )] }, controls=controls)
        except Exception as e:
            return str(e)

        if self.session.result['result'] == 0:
            return True
        else:
            return self.session.result['description']

    def modify_replace(self, object_dn, key, value, controls=None):
        try:
            self.session.modify(object_dn, {key: [( ldap3.MODIFY_REPLACE, [value] )] }, controls=controls)
        except Exception as e:
            return str(e)

        if self.session.result['result'] == 0:
            return True
        else:
            return self.session.result['description']

    def modify_delete(self, object_dn, key, value, controls=None):
        try:
            self.session.modify(object_dn, {key: [( ldap3.MODIFY_DELETE, [value] )] }, controls=controls)
        except Exception as e:
            return str(e)

        if self.session.result['result'] == 0:
            return True
        else:
            return self.session.result['description']

    def generate_rights_dict(self):

        rights_dict = {}

        self.session.search(self.configuration, '(objectCategory=CN=Control-Access-Right,%s)' % self.schema, attributes=['schemaIDGUID', 'rightsGuid', 'name'])

        for entry in self.session.entries:
            guid = str(entry['rightsGuid'][0])

            rights_dict[str(entry['name'][0])] = guid

        return rights_dict



