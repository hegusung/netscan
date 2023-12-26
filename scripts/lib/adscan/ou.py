from impacket.ldap import ldap, ldapasn1
from lib.adscan.accesscontrol import parse_accesscontrol, parse_sd, process_sid

from lib.adscan.gpo import GPO

class OU:

    privileged_sid_dict = {
        "S-1-5-32-544": "LocalAdmins", #"Administrators",
        "S-1-5-32-555": "RemoteDesktopUsers", #"Remote Desktop Users",
        "S-1-5-32-562": "DcomUsers", #"Distributed COM Users",
        "S-1-5-32-580": "PSRemoteUsers", #"Remote Management Users",
    }

    @classmethod
    def list(self, ldap_obj, smbscan, domain, domain_sid, callback):

        schema_guid_dict = ldap_obj._get_schema_guid_dict(['Organizational-Unit', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name'])

        def process(attr):
            ou_domain = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])

            if ou_domain.lower() != domain.lower():
                return

            dn = str(attr['distinguishedName'])

            b = bytes(attr['objectGUID'])
            guid = b[0:4][::-1].hex() + '-'
            guid += b[4:6][::-1].hex() + '-'
            guid += b[6:8][::-1].hex() + '-'
            guid += b[8:10].hex() + '-'
            guid += b[10:16].hex()

            # Process GPO
            links = {}
            gpo_paths = []
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

                    links[link.lower()] = {'IsEnforced': False if status == '0' else True}

                for link_dn, link_guid_path in ldap_obj._resolve_links(links.keys()).items():
                    links[link_dn.lower()]['GUID'] = link_guid_path[0].upper()
                    gpo_paths.append((link_guid_path[1], link_dn))

            # Resolve GPO effects
            gpo_effect = {}
            for sid in OU.privileged_sid_dict:
                gpo_effect[sid] = {}
                for t in ['Memberof', 'Members', 'Localgroup']:
                    gpo_effect[sid][t] = []

            for gpo_path, gpo_dn in gpo_paths:
                GPO.resolve_effect(smbscan, ldap_obj, gpo_dn, gpo_path, gpo_effect)
            gpo_effect = GPO.merge_gpo_effect(gpo_effect)

            aces = parse_sd(bytes(attr['nTSecurityDescriptor']), domain.upper(), 'organizational-unit', schema_guid_dict)

            callback({
                'domain': domain,
                'name': str(attr['name']),
                'dn': dn,
                'guid': guid,
                'links': list(links.values()),
                'gpo_effect': gpo_effect,
                'aces': aces,
            })

        sbase = "%s" % ldap_obj.defaultdomainnamingcontext
        search_filter='(objectCategory=organizationalUnit)'
        attributes = ['name', 'distinguishedName', 'objectGUID', 'nTSecurityDescriptor', 'gPLink']

        ldap_obj.query(process, sbase, search_filter, attributes, query_sd=True)


