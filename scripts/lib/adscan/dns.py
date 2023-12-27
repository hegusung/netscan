from datetime import datetime
from impacket.ldap.ldaptypes import LDAP_SID
from lib.adscan.accesscontrol import parse_sd, process_sid

class DNS:
    attributes = ['distinguishedName']

    @classmethod
    def list_dns(self, ldap):
        sbase = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % ldap.defaultdomainnamingcontext
        search_filter='(objectClass=dnsNode)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            dns = DNS(ldap, attr)

            yield dns

    # ==================
    # === DNS object ===
    # ==================

    def __init__(self, ldap, attr):
        self.dn = str(attr["distinguishedName"]).split(",CN=MicrosoftDNS,",1)[0]
        self.dns_entry = ".".join([item.split("=", 1)[-1] for item in str(attr['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])

        if '.DomainDnsZones.' in self.dns_entry:
            self.dns_entry = self.dns_entry.split('.DomainDnsZones.')[0]

    def to_json(self):
        return {
            'dns': self.dns_entry,
        }

