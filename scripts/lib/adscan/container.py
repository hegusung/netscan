from datetime import datetime
from impacket.ldap.ldaptypes import LDAP_SID
from lib.adscan.accesscontrol import parse_sd, process_sid
from lib.adscan.ou import OU
from lib.adscan.gpo import GPO

class Container:
    attributes = ['name', 'distinguishedName', 'nTSecurityDescriptor', 'objectGUID']
    schema_guid_attributes = ['container', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name']

    @classmethod
    def list_containers(self, ldap):
        schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)
        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter='(objectCategory=container)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            container = Container(ldap, attr, schema_guid_dict)

            yield container

    # ========================
    # === Container object ===
    # ========================

    def __init__(self, ldap, attr, schema_guid_dict):
        self.domain = ldap.dn_to_domain(str(attr['distinguishedName']))
        self.dn = str(attr['distinguishedName'])
        self.guid = ldap.parse_guid(bytes(attr['objectGUID']))
        self.name = str(attr['name'])

        self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'container', schema_guid_dict)

    def to_json(self):

        return {
            'domain': self.domain,
            'name': self.name,
            'dn': self.dn,
            'guid': self.guid,
            'aces': self.aces,
        }

