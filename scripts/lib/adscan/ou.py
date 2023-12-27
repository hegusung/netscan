from impacket.ldap import ldap, ldapasn1
from lib.adscan.accesscontrol import parse_accesscontrol, parse_sd, process_sid

from lib.adscan.gpo import GPO

class OU:
    attributes = ['name', 'distinguishedName', 'objectGUID', 'nTSecurityDescriptor', 'gPLink']
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

        #if ou_domain.lower() != domain.lower():
        #    return

        self.dn = str(attr['distinguishedName'])

        self.guid = ldap.parse_guid(bytes(attr['objectGUID']))

        # Process GPO
        self.links = {}
        self.gpo_paths = []
        if 'gPLink' in attr:
            for l in str(attr['gPLink']).split(']'):
                if len(l) == 0:
                    continue
                # Remove initial [
                l = l[1:]
                # Take after ://
                l = l.split('://')[-1]
                # Take before ;
                if len(l) == 0:
                    continue
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

        self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'organizational-unit', schema_guid_dict)

    def to_json(self):
        return {
            'domain': self.domain,
            'name': self.name,
            'dn': self.dn,
            'guid': self.guid,
            'links': list(self.links.values()),
            'gpo_effect': self.gpo_effect,
            'aces': self.aces,
        }

