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
        if attr['trustAttributes'] & 1 != 0:
            self.tags.append('Non-Transitive')
        if attr['trustAttributes'] & 2 != 0:
            self.tags.append('Uplevel clients only (Windows 2000 or newer)')
        if attr['trustAttributes'] & 4 != 0:
            self.tags.append('Quarantined Domain (External)')
        if attr['trustAttributes'] & 8 != 0:
            self.tags.append('Forest Trust')
        if attr['trustAttributes'] & 16 != 0:
            self.tags.append('Cross-Organizational Trust (Selective Authentication)')
        if attr['trustAttributes'] & 32 != 0:
            self.tags.append('Intra-Forest Trust (trust within the forest)')
        if attr['trustAttributes'] & 64 != 0:
            self.tags.append('Inter-Forest Trust (trust with another forest)')

    def to_json(self):
        return {
            'domain': self.domain,
            'direction': self.direction,
            'type': self.trust_type,
            'tags': self.tags,
        }

