from datetime import datetime
from impacket.ldap.ldaptypes import LDAP_SID
from lib.adscan.accesscontrol import parse_sd, process_sid

class Trust:
    attributes = ['distinguishedName', 'name', 'trustDirection', 'trustType', 'trustAttributes']

    @classmethod
    def list_trust(self, ldap):
        sbase = ldap.defaultdomainnamingcontext
        search_filter = '(objectClass=trustedDomain)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            trust = Trust(ldap, attr)

            yield trust

    # ====================
    # === Trust object ===
    # ====================

    def __init__(self, ldap, attr):
        self.domain = str(attr['name'])

        attr['trustDirection'] = int(str(attr['trustDirection']))
        if attr['trustDirection'] == 0:
            self.direction = 'Disabled'
        elif attr['trustDirection'] == 1:
            self.direction = 'Incoming'
        elif attr['trustDirection'] == 2:
            self.direction = 'Outgoing'
        elif attr['trustDirection'] == 3:
            self.direction = 'Bidirectional'
        else:
            self.direction = 'Unknown'

        attr['trustType'] = int(str(attr['trustType']))
        if attr['trustType'] == 1:
            self.trust_type = 'Windows NT'
        elif attr['trustType'] == 2:
            self.trust_type = 'Active Directory'
        elif attr['trustType'] == 3:
            self.trust_type = 'MIT/KRB realm trust'
        else:
            self.trust_type = 'Unknown'

        self.tags = []
        attr['trustAttributes'] = int(str(attr['trustAttributes']))
        if attr['trustAttributes'] & 0x1 != 0: # TRUST_ATTRIBUTE_NON_TRANSITIVE 
            self.tags.append('Non-Transitive')
        if attr['trustAttributes'] & 0x2 != 0: 
            self.tags.append('Uplevel clients only (Windows 2000 or newer)')
        if attr['trustAttributes'] & 0x4 != 0: # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN 
            self.tags.append('Quarantined Domain (External)')
        if attr['trustAttributes'] & 0x8 != 0: # TRUST_ATTRIBUTE_FOREST_TRANSITIVE 
            self.tags.append('Forest Transitive')
        if attr['trustAttributes'] & 0x10 != 0:
            self.tags.append('Cross-Organizational Trust (Selective Authentication)')
        if attr['trustAttributes'] & 0x20 != 0: # TRUST_ATTRIBUTE_WITHIN_FOREST 
            self.tags.append('Intra-Forest Trust (trust within the forest)')
        if attr['trustAttributes'] & 0x40 != 0: # TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL 
            self.tags.append('Treat as external')
        if attr['trustAttributes'] & 0x200 != 0: # TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION
            self.tags.append('No cross-organization TGT delegation')
        if attr['trustAttributes'] & 0x800 != 0: # TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION 
            self.tags.append('Cross-organization TGT delegation enabled')

        # Get the trust flavor
        if self.trust_type == 'MIT/KRB realm trust':
            self.trust_flavor = "Kerberos"
        elif self.trust_type == 'Unknown':
            self.trust_flavor = "Unknown"
        elif 'Intra-Forest Trust (trust within the forest)' in self.tags:
            self.trust_flavor = "Intra-Forest"
        else:
            if 'Forest Transitive' in self.tags:
                self.trust_flavor = "Forest"
            else:
                self.trust_flavor = "External"


        # Check SID filtering
        if 'Quarantined Domain (External)' in self.tags:
            self.tags.append('SID filtering enabled')
        else:
            if self.trust_flavor == 'Intra-Forest':
                self.tags.append('SID filtering disabled')
            elif self.trust_flavor == 'Forest':
                if 'Treat as external' in self.tags:
                    self.tags.append('SID filtering disabled')
                else:
                    self.tags.append('SID filtering enabled')
            elif self.trust_flavor == 'External':
                self.tags.append('SID filtering disabled')
            else:
                pass

    def to_json(self):
        return {
            'domain': self.domain,
            'direction': self.direction,
            'type': self.trust_flavor,
            'tags': self.tags,
        }

