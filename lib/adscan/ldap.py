import ldap3

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
                if attr['userAccountControl'] & 0x1000000 != 0:
                    tags.append('Trusted to auth for delegation')
            else:
                continue

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

            yield {
                'domain': domain,
                'groupname': groupname,
                'comment': comment,
                'sid': sid,
                'rid': rid,
                'dn': dn,
                'members': members,
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
            os = attr['operatingSystem'] if 'operatingSystem' in attr else None
            sid = attr['objectSid']
            rid = sid.split('-')[-1]
            comment = attr['description'] if 'description' in attr else None

            yield {
                'domain': domain,
                'hostname': hostname,
                'dns': dns,
                'os': os,
                'sid': sid,
                'rid': rid,
                'comment': comment,
            }


