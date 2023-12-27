from datetime import datetime
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
            aces2 = parse_sd(bytes(attr['msDS-GroupMSAMembership']), self.domain.upper(), 'user', schema_guid_dict)
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

