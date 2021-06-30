import ldap3
import re
import binascii
from utils.structure import Structure
from Cryptodome.Hash import MD4
import impacket
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA

class LDAPScan:

    def __init__(self, hostname, port, timeout, ssl=False):
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.ssl = ssl

        self.server = ldap3.Server(self.hostname, port=self.port, get_info=ldap3.ALL, connect_timeout=self.timeout, use_ssl=self.ssl)
        self.conn = None

    def url(self):
        method = "ldaps" if self.ssl else "ldap"
        return "%s://%s:%d" % (method, self.hostname, self.port)

    def connect(self, domain, username, password):
        if username == None:
            # Anonymous connection
            self.conn = ldap3.Connection(self.server)
        elif domain != None:
            self.conn = ldap3.Connection(self.server, user="%s\\%s" % (domain, username), password=password, authentication="NTLM")
        else:
            self.conn = ldap3.Connection(self.server, user=username, password=password)

        try:
            if self.conn.bind():

                # Gather info on service
                info = vars(self.server.info)
                self.defaultdomainnamingcontext = info["other"]["defaultNamingContext"]
                if type(self.defaultdomainnamingcontext) == list:
                    self.defaultdomainnamingcontext = "; ".join(self.defaultdomainnamingcontext)
                dnsHostName = info["other"]["dnsHostName"]
                if type(dnsHostName) == list:
                    dnsHostName = "; ".join(dnsHostName)
                self.current_domain = ".".join([item.split("=", 1)[-1] for item in self.defaultdomainnamingcontext.split(',') if item.split("=",1)[0].lower() == "dc"])

                return True, {'dns_hostname': dnsHostName, 'default_domain_naming_context': self.defaultdomainnamingcontext}
            else:
                return False, None
        except ldap3.core.exceptions.LDAPSocketOpenError:
            # timeout
            return False, None

    def disconnect(self):
        if self.conn.bind():
            self.conn.unbind()

        self.conn = None

    def list_users(self):
        entry_generator = self.conn.extend.standard.paged_search(search_base='%s' % self.defaultdomainnamingcontext,
                          search_filter="(objectCategory=user)",
                          search_scope=ldap3.SUBTREE,
                          attributes=ldap3.ALL_ATTRIBUTES,
                          get_operational_attributes=True,
                          paged_size = 100,
                          generator=True)

        for obj_info in entry_generator:
            try:
                attr = obj_info['attributes']
            except KeyError:
                continue

            if not 'sAMAccountName' in attr:
                continue

            domain = ".".join([item.split("=", 1)[-1] for item in attr['distinguishedName'].split(',') if item.split("=",1)[0].lower() == "dc"])
            username = attr['sAMAccountName']
            fullname = attr['displayName'] if 'displayName' in attr else ""
            comment = ",".join(attr['description']) if 'description' in attr else ""
            sid = attr['objectSid'] if 'objectSid' in attr else None
            if sid:
                rid = int(sid.split('-')[-1])
            else:
                rid = None
            dn = attr['distinguishedName']

            primaryGID = attr["primaryGroupID"]

            tags = []
            if 'userAccountControl' in attr:
                if attr['userAccountControl'] & 0x0200 == 0:
                    # not a user account
                    continue

                if attr['userAccountControl'] & 2 != 0:
                    tags.append('Account disabled')
                if attr['userAccountControl'] & 0x0020 != 0:
                    tags.append('Password not required')
                if attr['userAccountControl'] & 0x10000 != 0:
                    tags.append('Password never expire')
                if attr['userAccountControl'] & 0x400000 != 0:
                    tags.append('Don\'t require pre-auth')
                if attr['userAccountControl'] & 0x80000 != 0:
                    tags.append('Trusted to auth for delegation')
            else:
                continue

            if 'admincount' in attr and attr['admincount'] > 0:
                tags.append('admincount>0')

            yield {
                'domain': domain,
                'username': username,
                'fullname': fullname,
                'comment': comment,
                'sid': sid,
                'rid': rid,
                'dn': dn,
                'tags': tags,
            }

    def list_groups(self):
        entry_generator = self.conn.extend.standard.paged_search(search_base='%s' % self.defaultdomainnamingcontext,
                          search_filter="(objectCategory=group)",
                          search_scope=ldap3.SUBTREE,
                          attributes=ldap3.ALL_ATTRIBUTES,
                          get_operational_attributes=True)

        for obj_info in entry_generator:
            try:
                attr = obj_info['attributes']
            except KeyError:
                continue

            if not 'sAMAccountName' in attr:
                continue

            domain = ".".join([item.split("=", 1)[-1] for item in attr['distinguishedName'].split(',') if item.split("=",1)[0].lower() == "dc"])
            groupname = attr['sAMAccountName']
            comment = ",".join(attr['description']) if 'description' in attr else ""
            sid = attr['objectSid'] if 'objectSid' in attr else None
            if sid:
                rid = int(sid.split('-')[-1])
            else:
                rid = None

            primaryGID = attr["primaryGroupID"] if "primarygroupID" in attr else None

            dn = attr['distinguishedName']
            if 'member' in attr:
                members = attr['member']
            else:
                members = []

            tags = []
            if 'admincount' in attr and attr['admincount'] > 0:
                tags.append('admincount>0')

            yield {
                'domain': domain,
                'groupname': groupname,
                'comment': comment,
                'sid': sid,
                'rid': rid,
                'dn': dn,
                'members': members,
                'tags': tags,
            }

    def list_hosts(self):
        entry_generator = self.conn.extend.standard.paged_search(search_base='%s' % self.defaultdomainnamingcontext,
                          search_filter="(objectCategory=computer)",
                          search_scope=ldap3.SUBTREE,
                          attributes=ldap3.ALL_ATTRIBUTES,
                          get_operational_attributes=True,
                          paged_size = 100,
                          generator=True)

        for obj_info in entry_generator:
            try:
                attr = obj_info['attributes']
            except KeyError:
                continue

            if not 'dNSHostName' in attr:
                continue

            domain = ".".join([item.split("=", 1)[-1] for item in attr['distinguishedName'].split(',') if item.split("=",1)[0].lower() == "dc"])
            dns = attr["dNSHostName"]
            hostname = attr['name']
            os = attr['operatingSystem'] if 'operatingSystem' in attr else ''
            sid = attr['objectSid']
            rid = sid.split('-')[-1]
            comment = attr['description'] if 'description' in attr else ''

            tags = []
            if 'userAccountControl' in attr:
                if attr['userAccountControl'] & 0x80000 != 0:
                    tags.append('Trusted for delegation')

            yield {
                'domain': domain,
                'hostname': hostname,
                'dns': dns,
                'os': os,
                'sid': sid,
                'rid': rid,
                'tags': tags,
                'comment': comment,
            }

    def list_dns(self):
        entry_generator = self.conn.extend.standard.paged_search(search_base='CN=MicrosoftDNS,DC=DomainDnsZones,%s' % self.defaultdomainnamingcontext,
                                  search_filter="(objectClass=dnsNode)",
                                  search_scope=ldap3.SUBTREE,
                                  attributes=ldap3.ALL_ATTRIBUTES,
                                  get_operational_attributes=True,
                                  paged_size = 100,
                                  generator=True)

        for obj_info in entry_generator:
                try:
                    attr = obj_info['attributes']
                except KeyError:
                    continue

                dn = obj_info["dn"].split(",CN=MicrosoftDNS,",1)[0]
                dns_entry = ".".join([item.split("=", 1)[-1] for item in dn.split(',') if item.split("=",1)[0].lower() == "dc"])
                if not '.in-addr.arpa' in dns_entry:
                    yield dns_entry

    def list_trusts(self):
        entry_generator = self.conn.extend.standard.paged_search(search_base=self.defaultdomainnamingcontext,
                          search_filter="(objectClass=trustedDomain)",
                          search_scope=ldap3.SUBTREE,
                          attributes=ldap3.ALL_ATTRIBUTES,
                          get_operational_attributes=True,
                          paged_size = 100,
                          generator=True)

        for obj_info in entry_generator:
                try:
                    attr = obj_info['attributes']
                except KeyError:
                    continue

                domain = attr['name']

                if attr['trustDirection'] == 0:
                    direction = 'Disabled'
                elif attr['trustDirection'] == 1:
                    direction = 'Incoming'
                elif attr['trustDirection'] == 2:
                    direction = 'Outgoing'
                elif attr['trustDirection'] == 3:
                    direction = 'Bidirectional'
                else:
                    direction = 'Unknown'

                if attr['trustType'] == 1:
                    trust_type = 'Windows NT'
                elif attr['trustType'] == 2:
                    trust_type = 'Active Directory'
                elif attr['trustType'] == 3:
                    trust_type = 'MIT/KRB realm trust'
                else:
                    trust_type = 'Unknown'

                tags = []
                if attr['trustAttributes'] & 1 != 0:
                    tags.append('Non-Transitive')
                if attr['trustAttributes'] & 2 != 0:
                    tags.append('Uplevel clients only (Windows 2000 or newer)')
                if attr['trustAttributes'] & 4 != 0:
                    tags.append('Quarantined Domain (External)')
                if attr['trustAttributes'] & 8 != 0:
                    tags.append('Forest Trust')
                if attr['trustAttributes'] & 16 != 0:
                    tags.append('Cross-Organizational Trust (Selective Authentication)')
                if attr['trustAttributes'] & 32 != 0:
                    tags.append('Intra-Forest Trust (trust within the forest)')
                if attr['trustAttributes'] & 64 != 0:
                    tags.append('Inter-Forest Trust (trust with another forest)')

                yield {
                    'domain': domain,
                    'direction': direction,
                    'type': trust_type,
                    'tags': tags,
                }

    def list_cacerts(self):
        entry_generator = self.conn.extend.standard.paged_search(search_base='CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,%s' % self.defaultdomainnamingcontext,
                          search_filter="(cn=*)",
                          search_scope=ldap3.SUBTREE,
                          attributes=ldap3.ALL_ATTRIBUTES,
                          get_operational_attributes=True,
                          paged_size = 100,
                          generator=True)

        for obj_info in entry_generator:
                try:
                    attr = obj_info['attributes']
                except KeyError:
                    continue

                for cert_dict in attr['cACertificate']:
                    if cert_dict['encoding'] == 'base64':
                        b64_cert = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % cert_dict['encoded']
                        cert = x509.load_pem_x509_certificate(b64_cert.encode(), default_backend())

                        common_names = [cn.value for cn in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]

                        public_key = cert.public_key()
                        if type(public_key) in [RSAPublicKey, _RSAPublicKey]:
                            cert_algo = "RSA %d" % public_key.key_size
                        elif type(public_key) in [DSAPublicKey, _DSAPublicKey]:
                            cert_algo = "DSA %d" % public_key.key_size
                        elif type(public_key) in [EllipticCurvePublicKey, _EllipticCurvePublicKey]:
                            cert_algo = "EC %d" % public_key.key_size
                        else:
                            cert_algo = "Unknown: %s" % type(public_key)

                        yield {
                            'algo': cert_algo,
                            'common_names': common_names,
                        }
                    else:
                        yield {
                            'algo': "Unknown cert encoding: %s" % cert_dict['encoding'],
                            'common_names': [],
                        }

    def list_writable_GPOs(self, smbscan):
        entry_generator = self.conn.extend.standard.paged_search(search_base=self.defaultdomainnamingcontext,
                          search_filter="(objectCategory=groupPolicyContainer)",
                          search_scope=ldap3.SUBTREE,
                          attributes=ldap3.ALL_ATTRIBUTES,
                          get_operational_attributes=True,
                          paged_size = 100,
                          generator=True)

        share_pattern = re.compile("\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)(\\\\.*)")

        for obj_info in entry_generator:
                try:
                    attr = obj_info['attributes']
                except KeyError:
                    continue

                gpo_path = attr["gPCFileSysPath"]
                m = share_pattern.match(gpo_path)

                if m:
                    tid = None
                    fid = None
                    try:
                        tid = smbscan.conn.connectTree(m.group(2))
                        fid = smbscan.conn.openFile(tid, m.group(3) + "\\GPT.INI", desiredAccess=FILE_READ_DATA | FILE_WRITE_DATA)
                        smbscan.conn.closeFile(tid, fid)

                        writable = True
                    except impacket.smb.SessionError:
                        writable = False
                    except impacket.smbconnection.SessionError:
                        writable = False

                    if writable:
                        yield {
                            'name': attr['displayName'],
                            'path': attr['gPCFileSysPath'],
                        }

    # Taken from https://github.com/micahvandeusen/gMSADumper/blob/main/gMSADumper.py
    def dump_gMSA(self):
        entry_generator = self.conn.extend.standard.paged_search(search_base=self.defaultdomainnamingcontext,
                                  search_filter='(&(ObjectClass=msDS-GroupManagedServiceAccount))',
                                  search_scope=ldap3.SUBTREE,
                                  #attributes=ldap3.ALL_ATTRIBUTES,
                                  attributes=['distinguishedName', 'sAMAccountName','msDS-ManagedPassword'],
                                  get_operational_attributes=True,
                                  paged_size = 100,
                                  generator=True)

        for obj_info in entry_generator:
                try:
                    attr = obj_info['attributes']
                except KeyError:
                    continue
                try:
                    raw_attr = obj_info['raw_attributes']
                except KeyError:
                    continue

                domain = ".".join([item.split("=", 1)[-1] for item in attr['distinguishedName'].split(',') if item.split("=",1)[0].lower() == "dc"])
                username = attr['sAMAccountName']
                try:
                    data = obj_info['raw_attributes']['msDS-ManagedPassword'][0]
                    blob = MSDS_MANAGEDPASSWORD_BLOB()
                    blob.fromString(data)
                    hash = MD4.new ()
                    hash.update (blob['CurrentPassword'][:-2])
                    passwd = binascii.hexlify(hash.digest()).decode("utf-8")
                except KeyError:
                    passwd = 'Error: No msDS-ManagedPassword entry in LDAP'
                except IndexError:
                    passwd = 'Error: No msDS-ManagedPassword entry in LDAP'

                yield {
                    'domain': domain,
                    'username': username,
                    'password': passwd,
                }

    # Taken from https://github.com/n00py/LAPSDumper/blob/main/laps.py
    def dump_LAPS(self):
        entry_generator = self.conn.extend.standard.paged_search(search_base=self.defaultdomainnamingcontext,
                                  search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*))',
                                  search_scope=ldap3.SUBTREE,
                                  attributes=ldap3.ALL_ATTRIBUTES,
                                  #attributes=['distinguishedName', 'ms-MCS-AdmPwd', 'SAMAccountname'],
                                  get_operational_attributes=True,
                                  paged_size = 100,
                                  generator=True)

        for obj_info in entry_generator:
                try:
                    attr = obj_info['attributes']
                except KeyError:
                    continue

                domain = ".".join([item.split("=", 1)[-1] for item in attr['distinguishedName'].split(',') if item.split("=",1)[0].lower() == "dc"])
                dns = attr['dNSHostName']
                username = attr['sAMAccountName']
                passwd = attr['ms-Mcs-AdmPwd']

                yield {
                    'domain': domain,
                    'username': username,
                    'password': passwd,
                    'dns': dns,
                }

# Taken from https://github.com/micahvandeusen/gMSADumper/blob/main/gMSADumper.py

class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]
