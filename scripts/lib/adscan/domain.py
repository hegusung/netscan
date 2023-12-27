from datetime import datetime
from impacket.ldap.ldaptypes import LDAP_SID
from lib.adscan.accesscontrol import parse_sd, process_sid
from lib.adscan.ou import OU
from lib.adscan.gpo import GPO

class Domain:
    attributes = ['distinguishedName', 'name', 'objectSid', 'nTSecurityDescriptor', 'ms-DS-MachineAccountQuota', 'gPLink', 'msDS-Behavior-Version', 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts']
    schema_guid_attributes = ['domain', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name']

    @classmethod
    def list_domains(self, ldap, smb):
        schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)
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

        # Get domain parameters
        self.parameters = {}
        if 'ms-DS-MachineAccountQuota' in attr:
            self.parameters['ms-DS-MachineAccountQuota'] = int(attr['ms-DS-MachineAccountQuota'])
        if 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' in attr:
            self.parameters['msDS-ExpirePasswordsOnSmartCardOnlyAccounts'] = str(attr['msDS-ExpirePasswordsOnSmartCardOnlyAccounts'])

        # Get trusts
        self.trusts = ldap._resolve_trusts(self.domain)

        # Get links (GPOs)
        self.links = {}
        self.gpo_paths = []
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

            self.links[link.lower()] = {'IsEnforced': False if status == '0' else True}

        for link_dn, link_guid_path in ldap._resolve_links(self.links.keys()).items():
            self.links[link_dn.lower()]['GUID'] = link_guid_path[0].upper()
            self.gpo_paths.append((link_guid_path[1], link_dn))

        # Resolve GPO effects
        self.gpo_effect = {}
        for sid in OU.privileged_sid_dict:
            self.gpo_effect[sid] = {}
            for t in ['Memberof', 'Members', 'Localgroup']:
                self.gpo_effect[sid][t] = []

        for gpo_path, gpo_dn in self.gpo_paths:
            GPO.resolve_effect(smb, ldap, gpo_dn, gpo_path, self.gpo_effect)
        self.gpo_effect = GPO.merge_gpo_effect(self.gpo_effect)

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
            'functionallevel': self.functional_level,
            'trusts': self.trusts,
            'links': list(self.links.values()),
            'gpo_effect': self.gpo_effect,
            'aces': self.aces,
        }

