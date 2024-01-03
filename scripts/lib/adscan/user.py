import binascii
from datetime import datetime
from Cryptodome.Hash import MD4
from utils.structure import Structure
from impacket.ldap.ldaptypes import LDAP_SID
from lib.adscan.accesscontrol import parse_sd, process_sid

class User:
    attributes = ['objectClass', 'distinguishedName', 'sAMAccountname', 'displayName', 'description', 'objectSid', 'primaryGroupID', 'whenCreated', 'lastLogon', 'pwdLastSet', 'userAccountControl', 'adminCount', 'memberOf', 'nTSecurityDescriptor', 'msDS-GroupMSAMembership', 'servicePrincipalName', 'msDS-AllowedToDelegateTo', 'msDS-SupportedEncryptionTypes', 'sIDHistory']
    schema_guid_attributes = ['user', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name']
    schema_guid_dict = None

    @classmethod
    def get_schema_guid_dict(self, ldap):
        if self.schema_guid_dict == None:
            self.schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)

        return self.schema_guid_dict

    @classmethod
    def list_users(self, ldap):
        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter = '(|(objectCategory=user)(objectCategory=CN=ms-DS-Group-Managed-Service-Account,%s)(objectCategory=CN=ms-DS-Managed-Service-Account,%s))' % (ldap.schemanamingcontext, ldap.schemanamingcontext)

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            if not 'sAMAccountName' in attr:
                continue

            user = User(ldap, attr)

            yield user

    @classmethod
    def list_spns(self, ldap):
        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter = '(&(|(objectCategory=user)(objectCategory=CN=ms-DS-Group-Managed-Service-Account,%s)(objectCategory=CN=ms-DS-Managed-Service-Account,%s))(servicePrincipalName=*))' % (ldap.schemanamingcontext, ldap.schemanamingcontext)

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            if not 'sAMAccountName' in attr:
                continue

            user = User(ldap, attr)

            yield user

    @classmethod
    def list_donotrequirepreauth(self, ldap):
        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter = '(&(|(objectCategory=user)(objectCategory=CN=ms-DS-Group-Managed-Service-Account,%s)(objectCategory=CN=ms-DS-Managed-Service-Account,%s))(useraccountcontrol:1.2.840.113556.1.4.803:=4194304))' % (ldap.schemanamingcontext, ldap.schemanamingcontext)

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            if not 'sAMAccountName' in attr:
                continue

            user = User(ldap, attr)

            yield user

    @classmethod
    # Taken from https://github.com/micahvandeusen/gMSADumper/blob/main/gMSADumper.py
    def dump_gMSA(self, ldap):
        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
        attributes = self.attributes + ['msDS-ManagedPassword']

        for attr in ldap.query_generator(sbase, search_filter, attributes, query_sd=True):
            user = User(ldap, attr)

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

            yield user, passwd

    @classmethod
    def dump_sMSA(self, ldap):
        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter = "(objectClass=msDS-ManagedServiceAccount)"
        attributes = self.attributes + ['msDS-HostServiceAccountBL']

        for attr in ldap.query_generator(sbase, search_filter, attributes, query_sd=True):
            user = User(ldap, attr)

            if 'msDS-HostServiceAccountBL' in attr:
                target_host = str(attr['msDS-HostServiceAccountBL'])
            else:
                target_host = "Not linked to a host"

            yield user, target_host


    @classmethod
    def get_groups_recursive(self, ldap, name, groups={}, processed=[]):
        from lib.adscan.group import Group

        sbase = ldap.defaultdomainnamingcontext
        attributes = list(set(Group.attributes + ['objectClass', 'memberOf']))
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

        for attr in ldap.query_generator(sbase, search_filter, attributes, query_sd=True):

            sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()

            domain = ldap.dn_to_domain(str(attr['distinguishedName']))
            groupname = str(attr['sAMAccountName'])

            if type(attr['objectClass']) is list:
                object_class = [str(c) for c in attr['objectClass']]
            else:
                object_class = [str(attr['objectClass'])]

            # Processed, add it to list
            if 'group' in object_class:
                if not sid in groups:
                    groups[sid] = Group(ldap, attr)
                
            # Add the group specified by the "primaryGroupID" attribute to the list
            if 'primaryGroupID' in attr:
                obj_sid = sid.split('-')
                obj_sid[-1] = str(attr['primaryGroupID'])
                new_groups.append('-'.join(obj_sid))

            # Add the group specified by the "memberOf" attribute to the list
            if 'memberOf' in attr:
                if type(attr['memberOf']) == list:
                    for memberOf in attr['memberOf']:
                        new_groups.append(str(memberOf))
                else:
                    new_groups.append(str(attr['memberOf']))

        for g in new_groups:
            if not g in processed:
                processed.append(g)

                User.get_groups_recursive(ldap, g, groups=groups, processed=processed)

        return groups



    # ===================
    # === User object ===
    # ===================

    def __init__(self, ldap, attr):
        self.domain = ldap.dn_to_domain(str(attr['distinguishedName']))
        self.username = str(attr['sAMAccountName'])
        self.fullname = str(attr['displayName']) if 'displayName' in attr else ""
        
        if not 'description' in attr:
            self.comment = ""
        elif type(attr['description']) == list:
            self.comment = ",".join([str(s) for s in attr['description']])
        else:
            self.comment = str(attr['description'])

        self.sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical() if 'objectSid' in attr else None
        if self.sid:
            self.rid = int(self.sid.split('-')[-1])
        else:
            self.rid = None
        self.dn = str(attr['distinguishedName'])

        self.primaryGID = int(str(attr["primaryGroupID"]))

        try:
            self.created_date = datetime.strptime(str(attr['whenCreated']), '%Y%m%d%H%M%S.0Z') 
        except KeyError:
            self.created_date = None
        try:
            self.last_logon_date = datetime.fromtimestamp(ldap.getUnixTime(int(str(attr['lastLogon']))))
        except KeyError:
            self.last_logon_date = None
        try:
            self.last_password_change_date = datetime.fromtimestamp(ldap.getUnixTime(int(str(attr['pwdLastSet']))))
        except KeyError:
            self.last_password_change_date = None

        self.object_class = [str(c) for c in attr['objectClass']] 
        self.tags = []
        if 'msDS-GroupManagedServiceAccount' in self.object_class:
            self.tags.append('gMSA')
        elif 'msDS-ManagedServiceAccount' in self.object_class:
            self.tags.append('sMSA')
        elif 'user' in self.object_class:
            self.tags.append('User')

        if 'userAccountControl' in attr:
            attr['userAccountControl'] = int(str(attr['userAccountControl']))

            if attr['userAccountControl'] & 2 != 0:
                self.tags.append('Account disabled')
            if attr['userAccountControl'] & 0x0020 != 0:
                self.tags.append('Password not required')
            if attr['userAccountControl'] & 0x0080 != 0:
                self.tags.append('Encrypted text password allowed')
            if attr['userAccountControl'] & 0x0800 != 0:
                self.tags.append('Interdomain trust account')
            if attr['userAccountControl'] & 0x1000 != 0:
                self.tags.append('Workstation trust account')
            if attr['userAccountControl'] & 0x2000 != 0:
                self.tags.append('Server trust account')
            if attr['userAccountControl'] & 0x10000 != 0:
                self.tags.append('Password never expire')
            if attr['userAccountControl'] & 0x40000 != 0:
                self.tags.append('Smartcard required')
            if attr['userAccountControl'] & 0x80000 != 0:
                self.tags.append('Trusted for delegation')
            if attr['userAccountControl'] & 0x100000 != 0:
                self.tags.append('Account is sensitive and cannot be delegated')
            if attr['userAccountControl'] & 0x200000 != 0:
                self.tags.append('Use DES key only')
            if attr['userAccountControl'] & 0x400000 != 0:
                self.tags.append('Do not require pre-auth')
            if attr['userAccountControl'] & 0x1000000 != 0:
                self.tags.append('Trusted to auth for delegation')
            if attr['userAccountControl'] & 0x4000000 != 0:
                self.tags.append('Partial secrets account')
        else:
            pass
            #return

        if 'msDS-SupportedEncryptionTypes' in attr:
            attr['msDS-SupportedEncryptionTypes'] = int(str(attr['msDS-SupportedEncryptionTypes']))

            if attr['msDS-SupportedEncryptionTypes'] == 0:
                self.tags.append('KRB-RC4')
            if attr['msDS-SupportedEncryptionTypes'] & 1 != 0 or attr['msDS-SupportedEncryptionTypes'] & 2 != 0:
                self.tags.append('KRB-DES')
            if attr['msDS-SupportedEncryptionTypes'] & 4 != 0:
                self.tags.append('KRB-RC4')
            if attr['msDS-SupportedEncryptionTypes'] & 8 != 0:
                self.tags.append('KRB-AES128')
            if attr['msDS-SupportedEncryptionTypes'] & 16 != 0:
                self.tags.append('KRB-AES256')
        else:
            self.tags.append('KRB-RC4')

        # Not returned in the Global Catalog
        if 'adminCount' in attr and int(str(attr['adminCount'])) > 0:
            self.tags.append('adminCount>0')

        self.groups = [] 
        if 'memberOf' in attr:
            if type(attr['memberOf']) != list:
                attr['memberOf'] = [attr['memberOf']]

            for memberOf in attr['memberOf']:
                memberOf = str(memberOf)

                groupname = memberOf.split(',')[0].split('=')[-1]
                groupdomain = ldap.dn_to_domain(memberOf)

                self.groups.append("%s\\%s" % (groupdomain, groupname))

        # Check the ACEs
        try:
            self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'user', self.get_schema_guid_dict(ldap))
        except KeyError:
            self.aces = {}

        # Check the ACEs to access the gMSA account password
        if 'msDS-GroupMSAMembership' in attr:
            aces2 = parse_sd(bytes(attr['msDS-GroupMSAMembership']), self.domain.upper(), 'user', self.get_schema_guid_dict(ldap))
            for rule in aces2['aces']:
                if rule['RightName'] in ['GenericAll', 'Owns']:
                    rule['RightName'] = 'ReadGMSAPassword'
                    self.aces['aces'].append(rule)

        # Check the SPNs
        self.spns = []
        if 'servicePrincipalName' in attr:
            if type(attr['servicePrincipalName']) != list:
                attr['servicePrincipalName'] = [attr['servicePrincipalName']]

            for spn in attr['servicePrincipalName']:
                self.spns.append("%s" % spn)

        # Constrained delegation
        self.allowed_to_delegate_to = []
        if 'msDS-AllowedToDelegateTo' in attr:
            if type(attr['msDS-AllowedToDelegateTo']) != list:
                attr['msDS-AllowedToDelegateTo'] = [attr['msDS-AllowedToDelegateTo']]

            for item in attr['msDS-AllowedToDelegateTo']:
                self.allowed_to_delegate_to.append("%s" % item)

        # SID History
        self.sid_history = []
        if 'sIDHistory' in attr:
            if type(attr['sIDHistory']) != list:
                attr['sIDHistory'] = [attr['sIDHistory']]

            for item in attr['sIDHistory']:
                self.sid_history.append(LDAP_SID(bytes(item)).formatCanonical())

    def to_json(self):
        return {
            'domain': self.domain,
            'username': self.username,
            'fullname': self.fullname,
            'comment': self.comment,
            'created_date': self.created_date,
            'last_logon': self.last_logon_date,
            'last_password_change': self.last_password_change_date,
            'sid': self.sid,
            'rid': self.rid,
            'primary_gid': self.primaryGID,
            'dn': self.dn,
            'tags': self.tags,
            'group': self.groups,
            'aces': self.aces,
            'spns': self.spns,
            'allowed_to_delegate_to': self.allowed_to_delegate_to,
            'sid_history': self.sid_history,
        }
 
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
