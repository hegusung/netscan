from datetime import datetime
from impacket.ldap.ldaptypes import LDAP_SID
from lib.adscan.accesscontrol import parse_sd, process_sid
from lib.adscan.ou import OU
from lib.adscan.gpo import GPO

class Domain:
    attributes = ['distinguishedName', 'name', 'objectSid', 'nTSecurityDescriptor', 'ms-DS-MachineAccountQuota', 'gPLink', 'msDS-Behavior-Version', 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts', 'whenCreated']
    schema_guid_attributes = ['domain', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name']
    schema_guid_dict = None

    @classmethod
    def get_schema_guid_dict(self, ldap):
        if self.schema_guid_dict == None:
            self.schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)

        return self.schema_guid_dict


    @classmethod
    def list_domains(self, ldap, smb):
        schema_guid_dict = self.get_schema_guid_dict(ldap)

        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter = '(objectCategory=domain)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            domain = Domain(ldap, smb, attr, schema_guid_dict)

            yield domain

    # =====================
    # === Domain object ===
    # =====================

    def __init__(self, ldap, smb, attr, schema_guid_dict):
        self.domain = ldap.dn_to_domain(str(attr['distinguishedName']))
        self.domain_sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical() if 'objectSid' in attr else None
        self.dn = str(attr['distinguishedName'])
        self.name = str(attr['name'])

        try:
            self.created_date = datetime.strptime(str(attr['whenCreated']), '%Y%m%d%H%M%S.0Z') 
        except KeyError:
            self.created_date = None

        # Get domain parameters
        self.parameters = {}
        if 'ms-DS-MachineAccountQuota' in attr:
            self.parameters['ms-DS-MachineAccountQuota'] = int(attr['ms-DS-MachineAccountQuota'])
        if 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' in attr:
            self.parameters['msDS-ExpirePasswordsOnSmartCardOnlyAccounts'] = str(attr['msDS-ExpirePasswordsOnSmartCardOnlyAccounts'])

        self.gplink = str(attr['gPLink'])

        self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'domain', schema_guid_dict)

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
                self.functional_level = functional_levels[level]
            else:
                self.functional_level = "Unknown"
        else:
            self.functional_level = "Unknown"

        # dSHeuristics
        dSHeuristics = self.query_dsheuristics(ldap)
        if dSHeuristics != None:
            self.parameters['dSHeuristics'] = dSHeuristics

    def query_dsheuristics(self, ldap):
        dSHeuristics = None

        search_filter = "(dsHeuristics=*)"
        search_base = "CN=Directory Service,CN=Windows NT,CN=Services,%s" % ldap.configurationnamingcontext
        attributes = ['distinguishedName', 'dsHeuristics']

        for attr in ldap.query_generator(search_base, search_filter, attributes, query_sd=False):

            if 'dSHeuristics' in attr:
                dSHeuristics = str(attr['dSHeuristics'])
                break

        return dSHeuristics


    def to_json(self):
        return {
            'domain': self.domain,
            'name': self.name,
            'parameters': self.parameters,
            'sid': self.domain_sid,
            'dn': self.dn,
            'created_date': self.created_date,
            'functionallevel': self.functional_level,
            'gplink': self.gplink, 
            'aces': self.aces,
        }

