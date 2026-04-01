import re
import xml.etree.ElementTree as ET
import impacket
from impacket.smbconnection import SessionError
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA

from lib.smbscan.smb import SMBScan
from lib.search_secret.search_secret import SearchSecret

class GPOParser:

    def __init__(self, smb, ldap, dn, gpcpath):
        self.smb = smb
        self.ldap = ldap
        self.dn = dn
        self.gpcpath = gpcpath

        self.gpo_changes = []
        self.gpo_effect = {
            "Memberof": [],
            "Members": [],
            "Localgroup": [],
        }

        self.action_dict = {
            "U": "update",
            "C": "create",
            "R": "replace",
            "D": "delete",
        }

    def parse_gpo_files(self, search=None):

        self.resolve_local_admin_changes()
        
        self.resolve_script_changes(search)

        self.resolve_registry_changes()
        self.resolve_environment_changes()

        self.resolve_drives_changes()
        self.resolve_networkshares_changes()

        self.resolve_scheduledtasks_changes()

        self.resolve_files_changes(search)
        self.resolve_folder_changes()
        self.resolve_inifiles_changes()
        self.resolve_lnk_changes()

        self.resolve_registry_pol()

    def get_file(self, path):
        share_pattern = re.compile("\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)(\\\\.*)")

        try:

            if not path.lower().startswith("\\\\"):
                m = share_pattern.match(self.gpcpath)

                if m:
                    tid = self.smb.conn.connectTree(m.group(2))

                    try:
                        file_path = m.group(3) + "\\" + path
                        #print(file_path)
                        fid = self.smb.conn.openFile(tid, file_path, desiredAccess=FILE_READ_DATA)
                        file_data = self.smb.conn.readFile(tid, fid)
                        self.smb.conn.closeFile(tid, fid)
                    except SessionError:
                        file_data = None

                    return file_data

            else:
                sysvol_pattern = re.compile("\\\\\\\\[Ss][Yy][Ss][Vv][Oo][Ll]\\\\(\\\\.*)")
                m2 = sysvol_pattern.match(path)

                if m2:
                    tid = self.smb.conn.connectTree("SYSVOL")

                    try:
                        file_path = m2.group(1)
                        #print(file_path)
                        fid = self.smb.conn.openFile(tid, file_path, desiredAccess=FILE_READ_DATA)
                        file_data = self.smb.conn.readFile(tid, fid)
                        self.smb.conn.closeFile(tid, fid)
                    except SessionError:
                        file_data = None

                    return file_data
                else:
                    # Check if the provided path is just a standard \\server\share\path
                    m = share_pattern.match(path)

                    if m:
                        smb = SMBScan(m.group(1), 445, self.smb.timeout)
                        success = smb.connect()

                        if success:
                            success, _ = smb.auth(**self.smb.creds)

                            if success:
                                tid = smb.conn.connectTree(m.group(2))

                                try:
                                    file_path = m.group(3)

                                    fid = smb.conn.openFile(tid, file_path, desiredAccess=FILE_READ_DATA)
                                    file_data = smb.conn.readFile(tid, fid)
                                    smb.conn.closeFile(tid, fid)
                                except SessionError:
                                    file_data = None

                                return file_data

        except impacket.nmb.NetBIOSTimeout:
            pass

        return None

    def list_files(self, path):

        share_pattern = re.compile("\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)(\\\\.*)")
        m = share_pattern.match(self.gpcpath)

        contents = []
        try:
            file_path = m.group(3) + "\\" + path

            for file in self.smb.conn.listPath(m.group(2), file_path + '\\*'):
                filename = file.get_longname()
                size = file.get_filesize()

                if filename in ['.', '..']:
                    continue

                filepath = "\\\\%s\\%s\\%s\\%s\\%s" % (m.group(1), m.group(2), m.group(3), path, filename)
                contents.append((filepath, size))

        except SessionError:
            pass
        except impacket.nmb.NetBIOSError:
            pass
        except BrokenPipeError:
            pass
        except impacket.nmb.NetBIOSTimeout:
            pass

        return contents

    def list_shared_files(self, path):

        share_pattern = re.compile("\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)(\\\\.*)")
        m = share_pattern.match(path)

        contents = []
        try:
            if m:
                smb = SMBScan(m.group(1), 445, self.smb.timeout)
                success = smb.connect()

                if success:
                    success, _ = smb.auth(**self.smb.creds)

                    for file in smb.conn.listPath(m.group(2), m.group(3)):
                        filename = file.get_longname()
                        size = file.get_filesize()

                        if filename in ['.', '..']:
                            continue

                        if '*' in m.group(3):
                            filepath = "\\\\%s\\%s\\%s\\%s" % (m.group(1), m.group(2), m.group(3).split('*')[0], filename)
                        else:
                            filepath = "\\\\%s\\%s\\%s" % (m.group(1), m.group(2), m.group(3))
                        contents.append((filepath, size))

        except SessionError:
            pass
        except impacket.nmb.NetBIOSError:
            pass
        except BrokenPipeError:
            pass
        except impacket.nmb.NetBIOSTimeout:
            pass

        return contents


    def resolve_script_changes(self, search):
        for path in ["User\\Scripts\\Logon", "User\\Scripts\\Logoff", "Machine\\Scripts\\Startup", "Machine\\Scripts\\Shutdown"]:
            files = self.list_files(path)

            if files == None:
                continue

            for file in files:
                file_size = file[1]
                file = file[0]

                script_type = path.split('\\')[-1].lower()

                self.gpo_changes.append({
                    "type": "script_%s" % script_type,
                    "file": file,
                    "action": "Executing %s script at path %s" % (script_type, file)
                })

                if search != None:
                    ss = SearchSecret(keyword=search)

                    to_search = ss.to_check(file, file_size)

                    if to_search:
                        file_data = self.get_file(file)

                        if file_data != None:
                            ss.search_secret(file.split('\\')[-1], file, file_data, {})


    def resolve_registry_changes(self):
        for path in ["User", "Machine"]:
            file_data = self.get_file(path + "\\Preferences\\Registry\\Registry.xml")

            if file_data != None:
                try:
                    file_data = file_data.decode('utf-8')
                except UnicodeDecodeError as e:
                    file_data = file_data.decode('utf-16')

                root = ET.fromstring(file_data)

                if root.tag == "RegistrySettings":
                    for item in root:
                        if item.tag != "Registry":
                            continue

                        for prop in item:
                            if prop.tag != "Properties":
                                continue

                            action = self.action_dict[prop.attrib['action']]
                            hive = prop.attrib['hive'] if 'hive' in prop.attrib else None
                            key = prop.attrib['key'] if 'key' in prop.attrib else None
                            name = prop.attrib['name'] if 'name' in prop.attrib else None
                            value = str(prop.attrib['value']) if 'value' in prop.attrib else None

                            self.gpo_changes.append({
                                "type": "%s_registry" % action,
                                "registry": "%s\\%s" % (hive, key),
                                "name": name,
                                "value": value,
                                "action": "%s registry key %s\\%s with name \"%s\" and value \"%s\"" % (action.title(), hive, key, name, value)
                            })

    def resolve_files_changes(self, search):
        for path in ["User", "Machine"]:
            file_data = self.get_file(path + "\\Preferences\\Files\\Files.xml")

            if file_data != None:
                try:
                    file_data = file_data.decode('utf-8')
                except UnicodeDecodeError as e:
                    file_data = file_data.decode('utf-16')

                root = ET.fromstring(file_data)

                if root.tag == "Files":
                    for item in root:
                        if item.tag != "File":
                            continue

                        for prop in item:
                            if prop.tag != "Properties":
                                continue

                            action = self.action_dict[prop.attrib['action']]
                            srcfile = prop.attrib['fromPath'] if 'fromPath' in prop.attrib else None
                            dstfile = prop.attrib['targetPath'] if 'targetPath' in prop.attrib else None

                            self.gpo_changes.append({
                                "type": "%s_file" % action,
                                "srcfile": srcfile,
                                "dstfile": dstfile,
                                "action": "%s file. Copied from file \"%s\" to \"%s\"" % (action.title(), srcfile, dstfile)
                            })

                            if srcfile != None and srcfile.startswith('\\\\'):
                                ss = SearchSecret(keyword=search)

                                for file in self.list_shared_files(srcfile):
                                    file_size = file[1]
                                    file = file[0]
                                    print("> %s" % file)

                                    to_search = ss.to_check(file, file_size)

                                    if to_search:
                                        file_data = self.get_file(file)
                                        
                                        if file_data != None:
                                            ss.search_secret(file.split('\\')[-1], file, file_data, {})

    def resolve_folder_changes(self):
        for path in ["User", "Machine"]:
            file_data = self.get_file(path + "\\Preferences\\Folders\\Folders.xml")

            if file_data != None:
                try:
                    file_data = file_data.decode('utf-8')
                except UnicodeDecodeError as e:
                    file_data = file_data.decode('utf-16')

                root = ET.fromstring(file_data)

                if root.tag == "Folders":
                    for item in root:
                        if item.tag != "Folder":
                            continue

                        for prop in item:
                            if prop.tag != "Properties":
                                continue

                            action = self.action_dict[prop.attrib['action']]
                            folder = prop.attrib['path'] if 'path' in prop.attrib else None

                            self.gpo_changes.append({
                                "type": "%s_folder" % action,
                                "folder": folder,
                                "action": "%s folder \"%s\"" % (action.title(), folder)
                            })

    def resolve_inifiles_changes(self):
        for path in ["User", "Machine"]:
            file_data = self.get_file(path + "\\Preferences\\IniFiles\\IniFiles.xml")

            if file_data != None:
                try:
                    file_data = file_data.decode('utf-8')
                except UnicodeDecodeError as e:
                    file_data = file_data.decode('utf-16')

                root = ET.fromstring(file_data)

                if root.tag == "IniFiles":
                    for item in root:
                        if item.tag != "Ini":
                            continue

                        for prop in item:
                            if prop.tag != "Properties":
                                continue

                            action = self.action_dict[prop.attrib['action']]
                            inifile = prop.attrib['path'] if 'path' in prop.attrib else None
                            section = prop.attrib['section'] if 'section' in prop.attrib else None
                            key = prop.attrib['property'] if 'property' in prop.attrib else None
                            value = prop.attrib['value'] if 'value' in prop.attrib else None

                            self.gpo_changes.append({
                                "type": "%s_inifiles" % action,
                                "inifile": inifile,
                                "section": section,
                                "property": key,
                                "value": value,
                                "action": "%s ini file \"%s\". In section \"%s\" adds \"%s\" = \"%s\"" % (action.title(), inifile, section, key, value)
                            })

    def resolve_lnk_changes(self):
        for path in ["User", "Machine"]:
            file_data = self.get_file(path + "\\Preferences\\Shortcuts\\Shortcuts.xml")

            if file_data != None:
                try:
                    file_data = file_data.decode('utf-8')
                except UnicodeDecodeError as e:
                    file_data = file_data.decode('utf-16')

                root = ET.fromstring(file_data)

                if root.tag == "Shortcuts":
                    for item in root:
                        if item.tag != "Shortcut":
                            continue

                        for prop in item:
                            if prop.tag != "Properties":
                                continue

                            action = self.action_dict[prop.attrib['action']]
                            lnkfile = prop.attrib['shortcutPath'] if 'shortcutPath' in prop.attrib else None
                            target = prop.attrib['targetPath'] if 'targetPath' in prop.attrib else None
                            arguments = prop.attrib['arguments'] if 'arguments' in prop.attrib else None

                            self.gpo_changes.append({
                                "type": "%s_lnk" % action,
                                "file": lnkfile,
                                "target": target,
                                "arguments": arguments,
                                "action": "%s shortcut file \"%s\". Target \"%s\" arguments \"%s\"" % (action.title(), lnkfile, target, arguments)
                            })




    def resolve_environment_changes(self):
        for path in ["User", "Machine"]:
            file_data = self.get_file(path + "\\Preferences\\EnvironmentVariables\\EnvironmentVariables.xml")

            if file_data != None:
                try:
                    file_data = file_data.decode('utf-8')
                except UnicodeDecodeError as e:
                    file_data = file_data.decode('utf-16')

                root = ET.fromstring(file_data)

                if root.tag == "EnvironmentVariables":
                    for item in root:
                        if item.tag != "EnvironmentVariable":
                            continue

                        for prop in item:
                            if prop.tag != "Properties":
                                continue

                            action = self.action_dict[prop.attrib['action']]
                            name = prop.attrib['name'] if 'name' in prop.attrib else None
                            value = prop.attrib['value'] if 'value' in prop.attrib else None

                            self.gpo_changes.append({
                                "type": "%s_environment" % action,
                                "name": name,
                                "value": value,
                                "action": "%s environment variable \"%s\" with value \"%s\"" % (action.title(), name, value)
                            })

    def resolve_drives_changes(self):
        file_data = self.get_file("User\\Preferences\\Drives\\Drives.xml")

        if file_data != None:
            try:
                file_data = file_data.decode('utf-8')
            except UnicodeDecodeError as e:
                file_data = file_data.decode('utf-16')

            root = ET.fromstring(file_data)

            if root.tag == "Drives":
                for item in root:
                    if item.tag != "Drive":
                        continue

                    for prop in item:
                        if prop.tag != "Properties":
                            continue

                        action = self.action_dict[prop.attrib['action']]
                        drive = prop.attrib['letter'] if 'letter' in prop.attrib else None
                        label = prop.attrib['label'] if 'label' in prop.attrib else None
                        path = prop.attrib['path'] if 'path' in prop.attrib else None

                        self.gpo_changes.append({
                            "type": "%s_drive" % action,
                            "drive": drive,
                            "label": label,
                            "path": path,
                            "action": "%s drive %s:// (label: %s) located at %s" % (action.title(), drive, label, path)
                        })

    def resolve_networkshares_changes(self):
        file_data = self.get_file("Machine\\Preferences\\NetworkShares\\NetworkShares.xml")

        if file_data != None:
            try:
                file_data = file_data.decode('utf-8')
            except UnicodeDecodeError as e:
                file_data = file_data.decode('utf-16')

            root = ET.fromstring(file_data)

            if root.tag == "NetworkShareSettings":
                for item in root:
                    if item.tag != "NetShare":
                        continue

                    for prop in item:
                        if prop.tag != "Properties":
                            continue

                        action = self.action_dict[prop.attrib['action']]
                        name = prop.attrib['name'] if 'name' in prop.attrib else None
                        path = prop.attrib['path'] if 'path' in prop.attrib else None
                        comment = prop.attrib['comment'] if 'comment' in prop.attrib else None

                        self.gpo_changes.append({
                            "type": "%s_networkshare" % action,
                            "name": name,
                            "path": path,
                            "comment": comment,
                            "action": "%s network share %s (comment: %s) located at %s" % (action.title(), name, comment, path)
                        })

    def resolve_scheduledtasks_changes(self):

        for path in ["User", "Machine"]:
            file_data = self.get_file(path + "\\Preferences\\ScheduledTasks\\ScheduledTasks.xml")

            if file_data != None:
                try:
                    file_data = file_data.decode('utf-8')
                except UnicodeDecodeError as e:
                    file_data = file_data.decode('utf-16')

                root = ET.fromstring(file_data)

                if root.tag == "ScheduledTasks":
                    for item in root:
                        if item.tag != "Task":
                            continue

                        for prop in item:
                            if prop.tag != "Properties":
                                continue

                            action = self.action_dict[prop.attrib['action']]
                            name = prop.attrib['name'] if 'name' in prop.attrib else None
                            app = prop.attrib['appName'] if 'appName' in prop.attrib else None
                            if 'args' in prop.attrib and len(prop.attrib['args']) != 0:
                                app += " %s" % prop.attrib['args']

                            comment = prop.attrib['comment'] if 'comment' in prop.attrib else None

                            self.gpo_changes.append({
                                "type": "%s_scheduledtask" % action,
                                "name": name,
                                "app": app,
                                "comment": comment,
                                "action": "%s scheduled task %s (comment: %s) application: %s" % (action.title(), name, comment, app)
                            })


    def resolve_local_admin_changes(self):
        privileged_sid_dict = {
            "S-1-5-32-544": "LocalAdmins", #"Administrators",
            "S-1-5-32-555": "RemoteDesktopUsers", #"Remote Desktop Users",
            "S-1-5-32-562": "DcomUsers", #"Distributed COM Users",
            "S-1-5-32-580": "PSRemoteUsers", #"Remote Management Users",
        }

        file_data = self.get_file("MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf")

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
                    
                    # Case 1 : Members => members in a group (privileged)
                    from lib.adscan.ou import OU
                    if action_type == "Members":
                        if left.startswith('*'):
                            left = left[1:]

                        if left in OU.privileged_sid_dict:
                            members = []
                            for sid in right:
                                if sid.startswith('*'):
                                    sid = sid[1:]

                                members.append(sid)

                            self.gpo_effect["Members"].append({
                                'group': left,
                                'members': members,
                            })

                            self.gpo_changes.append({
                                "type": "add_members",
                                "group": left,
                                "members": members,
                                "action": "Adds %s as members of group %s" % (",".join(members), left)
                            })

                    # Case 2 : MemberOf => member of multiple groups (privileged)
                    elif action_type == "Memberof":
                        if left.startswith('*'):
                            left = left[1:]

                        for sid in right:
                            if sid.startswith('*'):
                                sid = sid[1:]

                            if sid in OU.privileged_sid_dict:
                                self.gpo_effect["Memberof"].append({
                                    'group': sid,
                                    'member': left,
                                })

                            self.gpo_changes.append({
                                "type": "add_members",
                                "group": sid,
                                "members": [left],
                                "action": "Adds %s as members of group %s" % (left, sid)
                            })

        file_data = self.get_file("MACHINE\\Preferences\\Groups\\Groups.xml")

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
                                from lib.adscan.gpo import GPO as gpo_obj
                                if groupName.lower() in gpo_obj.name_to_sid:
                                    groupSid = gpo_obj.name_to_sid[groupName.lower()]

                        from lib.adscan.ou import OU
                        if groupSid in OU.privileged_sid_dict:
                            if prop.attrib['deleteAllUsers'] == "1":
                                self.gpo_effect["Localgroup"].append({
                                    'action': "deleteAllUsers",
                                    'group': groupSid,
                                })

                                self.gpo_changes.append({
                                    "type": "delete_all_users",
                                    "group": groupSid,
                                    "action": "Delete all users from group %s" % (groupSid)
                                })


                            if prop.attrib['deleteAllGroups'] == "1":
                                self.gpo_effect["Localgroup"].append({
                                    'action': "deleteAllGroups",
                                    'group': groupSid,
                                })

                                self.gpo_changes.append({
                                    "type": "delete_all_groups",
                                    "group": groupSid,
                                    "action": "Delete all groups from group %s" % (groupSid)
                                })


                            for members in prop:
                                if members.tag != "Members":
                                    continue

                                for member in members:
                                    action = member.attrib['action']

                                    memberSid = member.attrib['sid'] if 'sid' in member.attrib else None
                                    memberName = member.attrib['name'] if 'name' in member.attrib else None

                                    if not memberSid:
                                        memberSid = memberName

                                    if memberSid:
                                        if action.lower() == "add":
                                            self.gpo_effect["Localgroup"].append({
                                                'action': 'add',
                                                'group': groupSid,
                                                'member': memberSid,
                                            })

                                            self.gpo_changes.append({
                                                "type": "add_members",
                                                "group": groupSid,
                                                "members": [memberSid],
                                                "action": "Adds %s as members of group %s" % (memberSid, groupSid)
                                            })

                                        elif action.lower() == "delete":
                                            self.gpo_effect["Localgroup"].append({
                                                'action': 'delete',
                                                'group': groupSid,
                                                'member': memberSid,
                                            })

                                            self.gpo_changes.append({
                                                "type": "delete_members",
                                                "group": groupSid,
                                                "members": [memberSid],
                                                "action": "Delete %s from group %s" % (memberSid, groupSid)
                                            })


    def resolve_registry_pol(self):
        """
        Contains (at least) Firewall and AppLocker config
        """

        for path in ["User", "Machine"]:
            file_data = self.get_file(path + "\\Registry.pol")

            if file_data != None:
                registry_data = parse_registry_pol(file_data)

                firewall_data = []
                applocker_data = {}

                for e in registry_data:
                    # Firewall
                    if e.key.lower() == "software\\policies\\microsoft\\windowsfirewall\\firewallrules":
                        if type(e.decoded) == bytes:
                            data = e.decoded.decode()
                        else:
                            data = e.decoded

                        firewall_data.append(data)
                    if e.key.lower().startswith("software\\policies\\microsoft\\windows\\srpv2\\"):
                        parts = e.key.split("\\")
                        if len(parts) > 5:
                            section = parts[5]

                            if not section in applocker_data:
                                applocker_data[section] = {
                                    "rules": [],
                                }

                            if len(parts) == 6:
                                if len(e.value_name) != 0:
                                    applocker_data[section][e.value_name] = e.decoded
                            else:

                                applocker_rule = {}
                                # Parse the XML
                                root = ET.fromstring(e.decoded)

                                applocker_rule['type'] = root.tag
                                applocker_rule['name'] = root.attrib['Name']
                                applocker_rule['description'] = root.attrib['Description']
                                applocker_rule['sid'] = root.attrib['UserOrGroupSid']
                                applocker_rule['action'] = root.attrib['Action']
                                applocker_rule['conditions'] = []

                                for condition in root:
                                    if not condition.tag == 'Conditions':
                                        continue

                                    for item in condition:
                                        if item.tag == 'FilePathCondition':
                                            applocker_rule['conditions'].append({'path': item.attrib['Path']})
                                        elif item.tag == 'FileHashCondition':
                                            hash_conditions = []
                                            for item2 in item:
                                                if item2.tag == 'FileHash':
                                                    hash_conditions.append({
                                                        'format': item2.attrib['Type'],
                                                        'hash': item2.attrib['Data'],
                                                        'file': item2.attrib['SourceFileName'],
                                                    })

                                            applocker_rule['conditions'].append({'hashs': hash_conditions})
                                        elif item.tag == 'FilePublisherCondition':

                                            version_ranges = []
                                            for item2 in item:
                                                if item2.tag == 'BinaryVersionRange':
                                                    version_ranges.append({
                                                        'low': item2.attrib['LowSection'],
                                                        'high': item2.attrib['HighSection'],
                                                    })
                                            publisher_condition = {
                                                'publisher': item.attrib['PublisherName'],
                                                'product': item.attrib['ProductName'],
                                                'binary': item.attrib['BinaryName'],
                                                'version_range': version_ranges,
                                            }
                                            applocker_rule['conditions'].append({'publisher': publisher_condition})

                                applocker_data[section]['rules'].append(applocker_rule)

                if len(firewall_data) != 0:
                    self.gpo_changes.append({
                        "type": "firewall",
                        "firewall_rules": firewall_data,
                        "action": "Firewall rules:\n" + "\n".join(firewall_data),
                    })
                elif applocker_data != {}:
                    self.gpo_changes.append({
                        "type": "applocker",
                        "applocker": applocker_data,
                        "action": applocker_rules_to_string(applocker_data),
                    })


def applocker_rules_to_string(rules):

    applocker_str = "Applocker rules:\n"
    for section, content in rules.items():
        applocker_str += "=========== %s ===========\n" % section
        for key, value in content.items():
            if key == 'rules':
                continue

            applocker_str += " - %s: %s\n" % (key, str(value))

        applocker_str += " - Rules:\n"
        for rule in content['rules']:
            applocker_str += "   * [%s] %s   (%s)  applies to: %s\n" % (rule['action'], rule['name'], rule['description'], rule['sid'])
            applocker_str += "     Conditions:\n"
            for cond in rule['conditions']:
                if 'path' in cond:
                    applocker_str += "       => Path: %s\n" % cond['path']
                elif 'hashs' in cond:
                    for h in cond['hashs']:
                        applocker_str += "       => Hash: (%s) %s:%s\n" % (h['file'], h['format'], h['hash'])
                elif 'publisher' in cond:
                    applocker_str += "       => Publisher: publisher:%s product:%s binary:%s  (%s)\n" % (cond['publisher']['publisher'], cond['publisher']['product'], cond['publisher']['binary'], ', '.join(["%s-%s" % (v['low'], v['high']) for v in cond['publisher']['version_range']]))
                else:
                    applocker_str += "       => %s\n" % cond
            applocker_str += "\n"
    return applocker_str 
                




from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Union

# Registry value type constants from MS-GPREG
# https://learn.microsoft.com/openspecs/windows_protocols/ms-gpreg
REG_SZ        = 0x01
REG_EXPAND_SZ = 0x02
REG_BINARY    = 0x03
REG_DWORD     = 0x04
REG_DWORD_BE  = 0x05
REG_MULTI_SZ  = 0x07
REG_QWORD     = 0x0B


@dataclass
class PolEntry:
    key: str
    value_name: str
    type: int          # numeric REG_* constant
    size: int          # size of raw_data in bytes (as stored in file)
    raw_data: bytes    # raw bytes from Data field
    decoded: Any       # best-effort decoded value (str/list/int/bytes)


def _decode_string(data: bytes) -> str:
    """
    Decode UTF-16LE string and strip trailing NULs.
    """
    return data.decode("utf-16le", errors="replace").rstrip("\x00")


def _decode_value(value_type: int, data: bytes) -> Any:
    """
    Interpret the Data field according to the registry type.
    """
    if value_type in (REG_SZ, REG_EXPAND_SZ):
        return _decode_string(data)

    if value_type == REG_MULTI_SZ:
        # MULTI_SZ: multiple UTF-16LE strings, separated by \x00, terminated by \x00\x00
        s = _decode_string(data)
        parts = [p for p in s.split("\x00") if p]
        return parts

    if value_type == REG_DWORD:
        if len(data) < 4:
            data = data.ljust(4, b"\x00")
        return int.from_bytes(data[:4], "little", signed=False)

    if value_type == REG_DWORD_BE:
        if len(data) < 4:
            data = data.rjust(4, b"\x00")
        return int.from_bytes(data[-4:], "big", signed=False)

    if value_type == REG_QWORD:
        if len(data) < 8:
            data = data.ljust(8, b"\x00")
        return int.from_bytes(data[:8], "little", signed=False)

    # REG_BINARY or unknown types → keep raw bytes
    return data


def _read_unicode_field(buf: bytes, idx: int, what: str) -> tuple[str, int]:
    """
    Read a UTF-16LE, NUL-terminated string followed by a ';' (UTF-16LE).

    Layout: <UTF-16 chars> 00 00 3B 00
                           ^^^^ ^^^^^^
                            NUL  ';'
    Returns (string, new_index).
    """
    terminator = b"\x00\x00;\x00"
    end = buf.find(terminator, idx)
    if end == -1:
        raise ValueError(f"Could not find terminator for {what} at offset {idx}")

    field_bytes = buf[idx:end]
    # Remove trailing NUL if present
    if field_bytes.endswith(b"\x00\x00"):
        field_bytes = field_bytes[:-2]

    text = field_bytes.decode("utf-16le", errors="replace")
    new_idx = end + len(terminator)
    return text, new_idx


def parse_registry_pol(data) -> List[PolEntry]:
    """
    Parse a Registry.pol / ntuser.pol file and return a list of PolEntry objects.
    """
    if len(data) < 8:
        raise ValueError("File too short to be a valid Registry.pol")

    # Header: Signature (4 bytes) + Version (4 bytes)
    signature = data[0:4]
    if signature != b"PReg":
        raise ValueError(f"Invalid signature {signature!r}, expected b'PReg'")

    version = int.from_bytes(data[4:8], "little", signed=False)
    # MS-GPREG currently documents version 1; others are rare but we just warn.
    if version != 1:
        # Don’t hard-fail, but you might want to log/raise depending on your use-case
        print(f"Warning: unexpected Registry.pol version {version}")

    idx = 8
    entries: List[PolEntry] = []

    wchar_open_bracket = "[".encode("utf-16le")  # b'[\x00'
    wchar_close_bracket = "]".encode("utf-16le") # b']\x00'
    wchar_semicolon = ";".encode("utf-16le")     # b';\x00'

    while idx + 2 <= len(data):
        # Skip padding NULs if present
        while idx + 2 <= len(data) and data[idx:idx+2] == b"\x00\x00":
            idx += 2

        if idx + 2 > len(data):
            break

        # Expect '[' (UTF-16LE)
        if data[idx:idx+2] != wchar_open_bracket:
            # No more instructions – most files end here
            break
        idx += 2

        # Key (UTF-16LE, NUL-terminated, then ';')
        key, idx = _read_unicode_field(data, idx, "key")

        # Value name (UTF-16LE, NUL-terminated, then ';')
        value_name, idx = _read_unicode_field(data, idx, "value_name")

        # Type: 4-byte little-endian DWORD, then ';' (UTF-16LE)
        if idx + 4 > len(data):
            raise ValueError("Unexpected end of file while reading value type")

        value_type = int.from_bytes(data[idx:idx+4], "little", signed=False)
        idx += 4

        if data[idx:idx+2] != wchar_semicolon:
            raise ValueError("Missing ';' after value type")
        idx += 2

        # Size: 4-byte little-endian DWORD, then ';' (UTF-16LE)
        if idx + 4 > len(data):
            raise ValueError("Unexpected end of file while reading value size")

        size = int.from_bytes(data[idx:idx+4], "little", signed=False)
        idx += 4

        if data[idx:idx+2] != wchar_semicolon:
            raise ValueError("Missing ';' after value size")
        idx += 2

        # Data: "size" bytes
        if idx + size > len(data):
            raise ValueError("Unexpected end of file while reading data")

        raw = data[idx:idx+size]
        idx += size

        # Closing ']' (UTF-16LE) – spec says Instruction ends with ']' character
        # Some writers may leave extra NULs before it for string types.
        # Skip any trailing NULs before the bracket.
        while idx + 2 <= len(data) and data[idx:idx+2] == b"\x00\x00":
            idx += 2

        if idx + 2 <= len(data) and data[idx:idx+2] == wchar_close_bracket:
            idx += 2
        else:
            # We don't strictly require it to keep the parser robust,
            # but if you want to be strict, uncomment the next line:
            # raise ValueError("Missing closing ']' after data")
            pass

        decoded = _decode_value(value_type, raw)

        entries.append(
            PolEntry(
                key=key,
                value_name=value_name,
                type=value_type,
                size=size,
                raw_data=raw,
                decoded=decoded,
            )
        )

    return entries
