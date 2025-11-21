import re
import xml.etree.ElementTree as ET
import impacket
from impacket.smbconnection import SessionError
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA

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

    def parse_gpo_files(self):

        self.resolve_local_admin_changes()
        
        self.resolve_script_changes()

        self.resolve_registry_changes()
        self.resolve_environment_changes()

        self.resolve_drives_changes()
        self.resolve_networkshares_changes()

        self.resolve_scheduledtasks_changes()

        self.resolve_files_changes()
        self.resolve_folder_changes()
        self.resolve_inifiles_changes()
        self.resolve_lnk_changes()

    def get_file(self, path):

        share_pattern = re.compile("\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)(\\\\.*)")
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
            return None

    def list_files(self, path):

        share_pattern = re.compile("\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)(\\\\.*)")
        m = share_pattern.match(self.gpcpath)

        contents = []
        try:
            file_path = m.group(3) + "\\" + path

            for file in self.smb.conn.listPath(m.group(2), file_path + '\\*'):
                filename = file.get_longname()

                if filename in ['.', '..']:
                    continue

                filepath = "\\\\%s\\%s\\%s\\%s" % (m.group(2), m.group(3), path, filename)
                contents.append(filepath)

        except SessionError:
            pass
        except impacket.nmb.NetBIOSError:
            pass
        except BrokenPipeError:
            pass

        return contents

    def resolve_script_changes(self):
        for path in ["User\\Scripts\\Logon", "User\\Scripts\\Logoff", "Machine\\Scripts\\Startup", "Machine\\Scripts\\Shutdown"]:
            files = self.list_files(path)

            if files == None:
                continue

            for file in files:
                script_type = path.split('\\')[-1].lower()

                self.gpo_changes.append({
                    "type": "script_%s" % script_type,
                    "file": file,
                    "action": "Executing %s script at path %s" % (script_type, file)
                })


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

    def resolve_files_changes(self):
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


