from datetime import datetime
from impacket.ldap.ldaptypes import LDAP_SID
from lib.adscan.accesscontrol import parse_sd, process_sid

class Group:
    attributes = ['distinguishedName', 'sAMAccountname', 'description', 'objectSid', 'primaryGroupID', 'adminCount', 'member', 'nTSecurityDescriptor', 'sIDHistory']
    schema_guid_attributes = ['group', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name']
    schema_guid_dict = None

    @classmethod
    def get_schema_guid_dict(self, ldap):
        if self.schema_guid_dict == None:
            self.schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)

        return self.schema_guid_dict

    @classmethod
    def list_groups(self, ldap):
        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter = '(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            if not 'sAMAccountName' in attr:
                continue

            group = Group(ldap, attr)

            yield group

    @classmethod
    def get_members_recursive(self, ldap, name, users={}, processed_groups=[]):
        from lib.adscan.user import User

        sbase = ldap.defaultdomainnamingcontext
        attributes = list(set(User.attributes + ['objectClass', 'member']))
        if type(name) == int:
            search_filter="(primaryGroupID=%d)" % name
        elif name.startswith('S-'):
            search_filter="(objectsid=%s)" % name
        elif name.startswith('CN='):
            name = name.replace('(', '\\28')
            name = name.replace(')', '\\29')
            search_filter="(distinguishedName=%s)" % name
        else:
            search_filter="(&(objectClass=group)(sAMAccountName=%s))" % name

        domain = None
        name = None
        for attr in ldap.query_generator(sbase, search_filter, attributes, query_sd=True):
            if not 'sAMAccountName' in attr:
                continue

            if type(attr['objectClass']) is list:
                object_class = [str(c) for c in attr['objectClass']]
            else:
                object_class = [str(attr['objectClass'])]

            domain = ldap.dn_to_domain(str(attr['distinguishedName']))
            name = str(attr['sAMAccountName'])

            if 'user' in object_class:
                user = User(ldap, attr) 

                domain_username = "%s\\%s" % (user.domain, user.username)

                if not domain_username in users:
                    users[domain_username] = user
            elif 'group' in object_class:
                sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical()

                if 'member' in attr:
                    if type(attr['member']) == list:
                        for member in attr['member']:
                            users, _ = self.get_members_recursive(ldap, str(member), users=users, processed_groups=processed_groups)
                    else:
                        users, _ = self.get_members_recursive(ldap, str(attr['member']), users=users, processed_groups=processed_groups)

                group_gid = int(sid.split('-')[-1])
                users, _ = self.get_members_recursive(ldap, group_gid, users=users, processed_groups=processed_groups)

        return users, "%s\\%s" % (domain, name)

    # ====================
    # === Group object ===
    # ====================

    def __init__(self, ldap, attr):
        self.domain = ldap.dn_to_domain(str(attr['distinguishedName']))
        self.groupname = str(attr['sAMAccountName'])
        self.fullname = str(attr['displayName']) if 'displayName' in attr else ""
        
        if not 'description' in attr:
            self.comment = ""
        elif type(attr['description']) == list:
            self.comment = ",".join([str(s) for s in attr['description']])
        else:
            self.comment = str(attr['description'])

        self.sid = LDAP_SID(bytes(attr['objectSid'])).formatCanonical() if 'objectSid' in attr else None
        if self.sid:
            self.rid = int(self.sid.split('-')[-1])
        else:
            self.rid = None
        self.dn = str(attr['distinguishedName'])

        self.tags = []
        # Not returned in the Global Catalog
        if 'adminCount' in attr and int(str(attr['adminCount'])) > 0:
            self.tags.append('adminCount>0')

        self.members = []
        if 'member' in attr:
            if type(attr['member']) == list:
                for member in attr['member']:
                    self.members = [str(m) for m in attr['member']]
            else:
                self.members = [str(attr['member'])]

        # Check the ACEs
        try:
            self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'group', self.get_schema_guid_dict(ldap))
        except KeyError:
            self.aces = {}

        # SID History
        self.sid_history = []
        if 'sIDHistory' in attr:
            if type(attr['sIDHistory']) != list:
                attr['sIDHistory'] = [attr['sIDHistory']]

            for item in attr['sIDHistory']:
                self.sid_history.append(LDAP_SID(bytes(item)).formatCanonical())

    def to_json(self):
        return {
            'domain': self.domain,
            'groupname': self.groupname,
            'comment': self.comment,
            'sid': self.sid,
            'rid': self.rid,
            'dn': self.dn,
            'members': self.members, # Changed to members from members_sid. Post-treatment can get info once all data is obtained from the DC
            'tags': self.tags,
            'aces': self.aces,
            'sid_history': self.sid_history,
        }

