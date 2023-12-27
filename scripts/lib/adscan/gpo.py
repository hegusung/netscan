import re
import xml.etree.ElementTree as ET
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SessionError
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA

from lib.adscan.accesscontrol import parse_accesscontrol, parse_sd, process_sid

class GPO:
    attributes = ['name', 'displayName', 'distinguishedName', 'objectGUID', 'nTSecurityDescriptor', 'gPCFileSysPath']
    schema_guid_attributes = ['Group-Policy-Container', 'ms-mcs-admpwd', 'ms-DS-Key-Credential-Link', 'Service-Principal-Name']

    name_to_sid = {
        'administrators': 'S-1-5-32-544',
        'remote desktop users': 'S-1-5-32-555',
        'distributed com users': 'S-1-5-32-562',
        'remote management users': 'S-1-5-32-580',
    }

    @classmethod
    def list_gpos(self, ldap):
        schema_guid_dict = ldap._get_schema_guid_dict(self.schema_guid_attributes)
        sbase = "%s" % ldap.defaultdomainnamingcontext
        search_filter = '(objectCategory=groupPolicyContainer)'

        for attr in ldap.query_generator(sbase, search_filter, self.attributes, query_sd=True):
            gpo = GPO(ldap, attr, schema_guid_dict)

            yield gpo

    @classmethod
    def resolve_effect(self, smbscan, ldap_obj, gpo_dn, gpo_path, gpo_effect):

        gpo_domain = ".".join([item.split("=", 1)[-1] for item in str(gpo_dn).split(',') if item.split("=",1)[0].lower() == "dc"])

        share_pattern = re.compile("\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)(\\\\.*)")
        m = share_pattern.match(gpo_path)
        if m:
            tid = smbscan.conn.connectTree(m.group(2))

            try:
                file_path = m.group(3) + "\\" + '\\'.join(["MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf"])
                #print(file_path)
                fid = smbscan.conn.openFile(tid, file_path, desiredAccess=FILE_READ_DATA)
                file_data = smbscan.conn.readFile(tid, fid)
                smbscan.conn.closeFile(tid, fid)
            except SessionError:
                file_data = None

            if file_data != None:
                try:
                    file_data = file_data.decode('utf-8')
                except UnicodeDecodeError as e:
                    file_data = file_data.decode('utf-16')

                #print("================\n%s\n================" % file_data)

                group_membership = False
                for line in file_data.split('\n'):
                    line = line.strip()

                    if len(line) == 0:
                        continue

                    if line.startswith('['):
                        if line.startswith('[Group Membership]'):
                            group_membership = True
                        else:
                            group_membership = False
                        continue

                    if group_membership:
                        left = line.split("=")[0].strip()
                        right = line.split("=")[-1].strip()
                        if len(right) != 0:
                            right = right.split(',')
                        else:
                            right = []

                        action_type = left.split("__")[-1]
                        left = left.split("__")[0]
                        
                        #print("####################")
                        #print(action_type)
                        #print(left)
                        #print(right)

                        from lib.adscan.ou import OU
                        if action_type == "Members":
                            if left.startswith('*'):
                                left = left[1:]

                            if left in OU.privileged_sid_dict:
                                members = []
                                for sid in right:
                                    if sid.startswith('*'):
                                        sid = sid[1:]

                                    if not sid.startswith('S-'):
                                        # to resolve
                                        sid = ldap_obj._resolve_name_to_sid(gpo_domain, sid)

                                    if sid != None and sid.startswith('S-') and len(sid.split('-')) == 8:
                                        # Domain SID
                                        members.append({
                                            'ObjectIdentifier': sid,
                                        })

                                # This replaces all previous entries
                                gpo_effect[left]["Members"] = members
                        elif action_type == "Memberof":
                            if left.startswith('*'):
                                left = left[1:]

                            if not left.startswith('S-'):
                                # to resolve
                                left = ldap_obj._resolve_name_to_sid(gpo_domain, left)

                            if left != None and left.startswith('S-') and len(left.split('-')) == 8:
                                # Domain SID
                                for sid in right:
                                    if sid.startswith('*'):
                                        sid = sid[1:]

                                    if sid in OU.privileged_sid_dict:
                                        gpo_effect[sid]["Memberof"].append({
                                            'ObjectIdentifier': left,
                                        })

            try:
                file_path = m.group(3) + "\\" + '\\'.join(["MACHINE", "Preferences", "Groups", "Groups.xml"])
                fid = smbscan.conn.openFile(tid, file_path, desiredAccess=FILE_READ_DATA)
                file_data = smbscan.conn.readFile(tid, fid)
                smbscan.conn.closeFile(tid, fid)
            except SessionError:
                file_data = None

            if file_data != None:
                file_data = file_data.decode()
                #print("================\n%s\n================" % file_data)

                root = ET.fromstring(file_data)

                if root.tag == "Groups":
                    for group in root:
                        if group.tag != "Group":
                            continue

                        for prop in group:
                            if prop.tag != "Properties":
                                continue

                            action = prop.attrib['action']
                            if action != "U":
                                continue

                            groupSid = prop.attrib['groupSid'] if 'groupSid' in prop.attrib else None
                            groupName = prop.attrib['groupName'] if 'groupName' in prop.attrib else None

                            if not groupSid:
                                if groupName:
                                    if groupName.lower() in self.name_to_sid:
                                        groupSid = self.name_to_sid[groupName.lower()]

                            from lib.adscan.ou import OU
                            if groupSid in OU.privileged_sid_dict:
                                if prop.attrib['deleteAllUsers'] == "1":
                                    for entry in gpo_effect[groupSid]['Localgroup']:
                                        if entry['ObjectType'] == 'User':
                                            del gpo_effect[groupSid]['Localgroup'][entry]

                                if prop.attrib['deleteAllGroups'] == "1":
                                    for entry in gpo_effect[groupSid]['Localgroup']:
                                        if entry['ObjectType'] == 'Group':
                                            del gpo_effect[groupSid]['Localgroup'][entry]

                                for members in prop:
                                    if members.tag != "Members":
                                        continue

                                    for member in members:
                                        action = member.attrib['action']

                                        memberSid = member.attrib['sid'] if 'sid' in member.attrib else None
                                        memberName = member.attrib['name'] if 'name' in member.attrib else None

                                        if not memberSid:
                                            memberSid = ldap_obj._resolve_name_to_sid(gpo_domain, memberName)

                                        if memberSid:
                                            if action.lower() == "add":
                                                gpo_effect[groupSid]['Localgroup'].append({
                                                    'ObjectIdentifier': memberSid,
                                                })

                                            elif action.lower() == "delete":
                                                for entry in gpo_effect[groupSid]['Localgroup']:
                                                    if entry['ObjectIdentifier'] == memberSid:
                                                        del gpo_effect[groupSid]['Localgroup'][entry]



        return ldap_obj._resolve_sid_types(gpo_effect, 'gpo_effect')

    @classmethod
    def merge_gpo_effect(self, gpo_effect):

        from lib.adscan.ou import OU
        out = {}
        for localgroup_sid, item in gpo_effect.items():
            localgroup_key = OU.privileged_sid_dict[localgroup_sid]

            entries = item["Memberof"]
            if len(item["Members"]) != 0:
                entries += item["Members"]
            else:
                entries += item["Localgroup"]

            out[localgroup_key] = entries

        return out

    # ==================
    # === GPO object ===
    # ==================

    def __init__(self, ldap, attr, schema_guid_dict):
        self.domain = ldap.dn_to_domain(str(attr['distinguishedName']))
        self.domain_dn = ",".join(["DC=%s" % p for p in self.domain.split('.')])
        self.domain_sid = ldap.resolve_dn_to_sid([self.domain_dn])[0]
        self.gpcpath = str(attr['gPCFileSysPath'])
        self.name = str(attr['displayName'])

        self.dn = str(attr['distinguishedName'])

        self.guid = ldap.parse_guid(bytes(attr['objectGUID']))

        self.aces = parse_sd(bytes(attr['nTSecurityDescriptor']), self.domain.upper(), 'group-policy-container', schema_guid_dict)


    def to_json(self):
        return {
            'domain': self.domain,
            'domain_sid': self.domain_sid,
            'name': self.name,
            'dn': self.dn,
            'guid': self.guid,
            'gpcpath': self.gpcpath,
            'aces': self.aces,
        }


