from impacket.ldap import ldap, ldapasn1
from lib.adscan.accesscontrol import parse_accesscontrol, parse_sd, process_sid
from datetime import datetime

from lib.adscan.gpo import GPO

class OU:
    attributes = ['name', 'distinguishedName', 'objectGUID', 'nTSecurityDescriptor', 'gPLink', 'description', 'whenCreated', 'gPOptions']
    schema_guid_attributes = ['Organizational-Unit', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name']

    privileged_sid_dict = {
        "S-1-5-32-544": "LocalAdmins", #"Administrators",
        "S-1-5-32-555": "RemoteDesktopUsers", #"Remote Desktop Users",
        "S-1-5-32-562": "DcomUsers", #"Distributed COM Users",
        "S-1-5-32-580": "PSRemoteUsers", #"Remote Management Users",
    }

    @classmethod
    def list_ous(self, ldap, smb):
        schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)

        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter='(objectCategory=organizationalUnit)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            ou = OU(ldap, smb, attr, schema_guid_dict)

            yield ou

    # ==================
    # === OU object ===
    # ==================


    def __init__(self, ldap, smb, attr, schema_guid_dict):
        self.domain = ldap.dn_to_domain(str(attr['distinguishedName']))
        self.name = str(attr['name'])
        self.description = str(attr['description']) if 'description' in attr else ''

        try:
            self.created_date = datetime.strptime(str(attr['whenCreated']), '%Y%m%d%H%M%S.0Z') 
        except KeyError:
            self.created_date = None

        if 'gPOptions' in attr:
            self.gPOptions = int(attr['gPOptions'])
        else:
            self.gPOptions = None

        self.dn = str(attr['distinguishedName'])

        self.guid = ldap.parse_guid(bytes(attr['objectGUID']))

        if 'gPLink' in attr:
            self.gplink = str(attr['gPLink'])
        else:
            self.gplink = ""

        self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'organizational-unit', schema_guid_dict)

    def to_json(self):
        return {
            'domain': self.domain,
            'name': self.name,
            'dn': self.dn,
            'guid': self.guid,
            'gplink': self.gplink, 
            'aces': self.aces,
            'description': self.description,
            'created_date': self.created_date,
            'gPOptions': self.gPOptions,
        }

