from datetime import datetime
from impacket.ldap.ldaptypes import LDAP_SID
from lib.adscan.accesscontrol import parse_sd, process_sid

class Host:
    attributes = ['distinguishedName', 'sAMAccountname', 'dNSHostName', 'name', 'operatingSystem', 'description', 'objectSid', 'userAccountControl', 'nTSecurityDescriptor', 'primaryGroupID', 'servicePrincipalName', 'whenCreated', 'lastLogon', 'pwdLastSet', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'msDS-SupportedEncryptionTypes']
    schema_guid_attributes = ['computer', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name']

    @classmethod
    def list_hosts(self, ldap):
        schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)
        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter = '(objectCategory=computer)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            if not 'sAMAccountName' in attr:
                continue

            host = Host(ldap, attr, schema_guid_dict)

            yield host

    # ===================
    # === Host object ===
    # ===================

    def __init__(self, ldap, attr, schema_guid_dict):
        self.domain = ldap.dn_to_domain(str(attr['distinguishedName']))
        self.dns = str(attr["dNSHostName"]) if 'dNSHostName' in attr else ''
        self.hostname = str(attr['name'])
        self.os = str(attr['operatingSystem']) if 'operatingSystem' in attr else ''
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

        self.tags = []
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

        # Check the ACEs
        try:
            self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'computer', schema_guid_dict)
        except KeyError:
            self.aces = {}

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

        # Ressourse-Based Constrained delegation
        self.allowed_to_act_on_behalf_of_other_identity_sids = []
        if 'msDS-AllowedToActOnBehalfOfOtherIdentity' in attr:
            aces = parse_sd(bytes(attr['msDS-AllowedToActOnBehalfOfOtherIdentity']), self.domain.upper(), 'computer', schema_guid_dict)
            for ace in aces['aces']:
                if ace['RightName'] == 'GenericAll':
                    self.allowed_to_act_on_behalf_of_other_identity_sids.append(ace['PrincipalSID'])

        self.allowed_to_act_on_behalf_of_other_identity = []
        for sid_obj in self.allowed_to_act_on_behalf_of_other_identity_sids:
            name = ldap._resolve_sid_to_name(self.domain, sid_obj)
            self.allowed_to_act_on_behalf_of_other_identity.append(name)

    def to_json(self):
        return {
            'domain': self.domain,
            'hostname': self.hostname,
            'dns': self.dns,
            'os': self.os,
            'sid': self.sid,
            'rid': self.rid,
            'primary_gid': self.primaryGID,
            'dn': self.dn,
            'tags': self.tags,
            'comment': self.comment,
            'aces': self.aces,
            'spns': self.spns,
            'allowed_to_delegate_to': self.allowed_to_delegate_to,
            'allowed_to_act_on_behalf_of_other_identity': self.allowed_to_act_on_behalf_of_other_identity,
            'allowed_to_act_on_behalf_of_other_identity_sids': self.allowed_to_act_on_behalf_of_other_identity_sids,
            'created_date': self.created_date,
            'last_logon': self.last_logon_date,
            'last_password_change': self.last_password_change_date,
        }
