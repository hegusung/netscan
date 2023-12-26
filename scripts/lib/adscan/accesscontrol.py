import sys
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import LDAP_SID
#import ldap3

sid_name_dict = {
    'S-1-5-10': 'Principal Self',
    'S-1-3-0': 'Creator Owner',
    'S-1-1-0': 'Everyone',
    'S-1-5-18': 'Local System',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-9': 'Enterprise Domain Controlers',
    'S-1-5-20': 'Network Service',
}

rights_dict = {
    'GenericAll': 983551,
    'GenericWrite': 131112,
    'WriteDACL': 262144,
    'WriteOwner': 524288,
    'WriteProperty': 0x20,
    'ControlAccess': 0x100,
    'CreateChild': 0x1,
    'DeleteChild': 0x2,
    'ReadProperty': 0x10,
    'Self': 0x8,
}

extended_rights = {
    '00299570-246d-11d0-a768-00aa006e0529': 'UserForceChangePassword',
    'e362ed86-b728-0842-b27d-2dea7a9df218': 'ReadGMSAPassword',
    'e503b3aa-d05d-44ab-85fa-04fa08251e25': 'ReadLAPSPassword',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'property:servicePrincipalName',
    'e48d0154-bcf8-11d1-8702-00c04fb96050': 'propertySet:PublicInformation',
    '0e10c968-78fb-11d2-90d4-00c04f79dc55': 'Certificate-Enrollment',
    'bf9679c0-0de6-11d0-a285-00aa003049e2': 'WriteMember',
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79': 'AllowedToAct',
    '4c164200-20c0-11d0-a768-00aa006e0529': 'UserAccountRestrictionsSet',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'GetChanges',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'GetChangesAll',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'GetChangesInFilteredSet',
}

def get_owner(aces):
    if 'aces' in aces:
        for ace in aces['aces']:
            if ace['RightName'] == 'Owns':
                return ace['PrincipalSID'] 

    return ''

def parse_accesscontrol(security_descriptor, ldap):
    a = SR_SECURITY_DESCRIPTOR()
    a.fromString(security_descriptor)

    sid = parse_sid(a['OwnerSid'])
    name = search_name(sid, ldap)
    yield {
        'type': '',
        'sid': sid,
        'name': name,
        'rights': ['Owns'],
    }

    for ace_b in a['Dacl'].aces:
        ace = parse_ace(ace_b)

        name = search_name(ace['sid'], ldap)
        ace['name'] = name

        yield ace

def can_write_property(ace, guid_property):
    if not 'WriteProperty' in ace['rights']:
        return False
    if not 'OBJECT_TYPE_PRESENT' in ace['flags']:
        return True
    if ace['guid'] in extended_rights and extended_rights[ace['guid']] == guid_property:
        return True

    return False

def has_extended_right(ace, guid_property):
    if not 'ControlAccess' in ace['rights']:
        return False
    if not 'OBJECT_TYPE_PRESENT' in ace['flags']:
        return True
    if ace['guid'] in extended_rights and extended_rights[ace['guid']] == guid_property:
        return True

    return False

def process_sid(domain_name, sid):
    for s in list(sid_name_dict.keys()) + ['S-1-5-32']:
        if sid.startswith(s):
            sid = "%s-%s" % (domain_name, sid)

    return sid

def parse_sd(sd_bytes, domain_name, object_type, schema_guid_dict):
    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(sd_bytes)

    res = {}

    res['is_acl_protected'] = (int(sd['Control']) & 3) != 0

    sid = process_sid(domain_name, parse_sid(sd['OwnerSid']))
    res['aces'] = [{"PrincipalSID": sid, "RightName": "Owns", "IsInherited": False}]

    for ace_b in sd['Dacl'].aces:
        ace = parse_ace(ace_b)

        sid = process_sid(domain_name, ace['sid'])

        if sid.endswith('S-1-5-18'):
            continue

        if ace['type'] == 'ACCESS_ALLOWED_ACE':
            if not ace['inherited'] and ace['inherit_only_ace']:
                continue

            if 'GenericAll' in ace['rights']:
                res['aces'].append({"PrincipalSID": sid, "RightName": "GenericAll", "IsInherited": ace['inherited']})
            else:
                if 'GenericWrite' in ace['rights'] or 'WriteProperty' in ace['rights']:
                    if object_type in ['user', 'group', 'computer', 'group-policy-container']:
                        res['aces'].append({"PrincipalSID": sid, "RightName": "GenericWrite", "IsInherited": ace['inherited']})
                if 'WriteOwner' in ace['rights']:
                    res['aces'].append({"PrincipalSID": sid, "RightName": "WriteOwner", "IsInherited": ace['inherited']})
                if 'WriteDACL' in ace['rights']:
                    res['aces'].append({"PrincipalSID": sid, "RightName": "WriteDacl", "IsInherited": ace['inherited']})
                if 'ControlAccess' in ace['rights']:
                    if object_type in ['user', 'domain']:
                        res['aces'].append({"PrincipalSID": sid, "RightName": "AllExtendedRights", "IsInherited": ace['inherited']})
                    elif object_type == 'computer' and not sid.endswith('S-1-5-32-544') and not sid.endswith('-512'):
                        res['aces'].append({"PrincipalSID": sid, "RightName": "AllExtendedRights", "IsInherited": ace['inherited']})

        elif ace['type'] == 'ACCESS_ALLOWED_OBJECT_ACE':
            if not ace['inherited'] and ace['inherit_only_ace']:
                continue

            # Check if the ACE has restrictions on object type (inherited case)
            if ace['inherited'] and 'INHERITED_OBJECT_TYPE_PRESENT' in ace['flags']:
                 # Verify if the ACE applies to this object type
                 if not object_type in schema_guid_dict or ace['inherited_guid'] != schema_guid_dict[object_type]:
                     continue

            # Check generic access masks first
            if 'GenericAll' in ace['rights'] or 'GenericWrite' in ace['rights'] or 'WriteOwner' in ace['rights'] or 'WriteDACL' in ace['rights']:
                if not object_type in schema_guid_dict or 'OBJECT_TYPE_PRESENT' in ace['flags'] and ace['guid'] != schema_guid_dict[object_type]:
                    continue

                if 'GenericAll' in ace['rights']:
                    if object_type == 'computer' and 'OBJECT_TYPE_PRESENT' in ace['flags'] and ace['guid'] == schema_guid_dict['ms-mcs-admpwd']:  
                        res['aces'].append({"PrincipalSID": sid, "RightName": "ReadLAPSPassword", "IsInherited": ace['inherited']})
                    else:
                        res['aces'].append({"PrincipalSID": sid, "RightName": "GenericAll", "IsInherited": ace['inherited']})
                else:
                    if 'GenericWrite' in ace['rights']:
                        res['aces'].append({"PrincipalSID": sid, "RightName": "GenericWrite", "IsInherited": ace['inherited']})
                    if 'WriteOwner' in ace['rights']:
                        res['aces'].append({"PrincipalSID": sid, "RightName": "WriteOwner", "IsInherited": ace['inherited']})
                    if 'WriteDACL' in ace['rights']:
                        res['aces'].append({"PrincipalSID": sid, "RightName": "WriteDacl", "IsInherited": ace['inherited']})

            if 'WriteProperty' in ace['rights']:
                if object_type in ['user', 'group', 'computer', 'group-policy-container'] and not 'OBJECT_TYPE_PRESENT' in ace['flags']:
                    res['aces'].append({"PrincipalSID": sid, "RightName": "GenericWrite", "IsInherited": ace['inherited']})
                if object_type in ['group'] and can_write_property(ace, "WriteMember"):
                    res['aces'].append({"PrincipalSID": sid, "RightName": "AddMember", "IsInherited": ace['inherited']})
                if object_type in ['computer'] and can_write_property(ace, "AllowedToAct"):
                    res['aces'].append({"PrincipalSID": sid, "RightName": "AddAllowedToAct", "IsInherited": ace['inherited']})
                if object_type in ['computer'] and can_write_property(ace, "UserAccountRestrictionsSet") and not sid.endswith("-512"):
                    res['aces'].append({"PrincipalSID": sid, "RightName": "WriteAccountRestrictions", "IsInherited": ace['inherited']})
                if object_type in ['user', 'computer'] and 'OBJECT_TYPE_PRESENT' in ace['flags'] and 'ms-ds-key-credential-link' in schema_guid_dict and ace['guid'] == schema_guid_dict['ms-ds-key-credential-link']:  
                    res['aces'].append({"PrincipalSID": sid, "RightName": "AddKeyCredentialLink", "IsInherited": ace['inherited']})
                if object_type in ['user'] and 'OBJECT_TYPE_PRESENT' in ace['flags'] and ace['guid'] == schema_guid_dict['service-principal-name']:  
                    res['aces'].append({"PrincipalSID": sid, "RightName": "WriteSPN", "IsInherited": ace['inherited']})
            elif 'Self' in ace['rights']:
                if object_type in ['group'] and ace['guid'] in extended_rights and extended_rights[ace['guid']] == "WriteMember":
                    res['aces'].append({"PrincipalSID": sid, "RightName": "AddSelf", "IsInherited": ace['inherited']})

            if 'ReadProperty' in ace['rights']:
                if object_type in ['computer'] and 'OBJECT_TYPE_PRESENT' in ace['flags'] and 'ms-mcs-admpwd' in schema_guid_dict and ace['guid'] == schema_guid_dict['ms-mcs-admpwd']:
                    res['aces'].append({"PrincipalSID": sid, "RightName": "ReadLAPSPassword", "IsInherited": ace['inherited']})

            if 'ControlAccess' in ace['rights']:
                if object_type in ['user', 'domain'] and not 'OBJECT_TYPE_PRESENT' in ace['flags']:  
                    res['aces'].append({"PrincipalSID": sid, "RightName": "AllExtendedRights", "IsInherited": ace['inherited']})
                if object_type in ['computer'] and not 'OBJECT_TYPE_PRESENT' in ace['flags']:  
                    res['aces'].append({"PrincipalSID": sid, "RightName": "AllExtendedRights", "IsInherited": ace['inherited']})
                if object_type in ['domain'] and has_extended_right(ace, "GetChanges"):
                    res['aces'].append({"PrincipalSID": sid, "RightName": "GetChanges", "IsInherited": ace['inherited']})
                if object_type in ['domain'] and has_extended_right(ace, "GetChangesAll"):
                    res['aces'].append({"PrincipalSID": sid, "RightName": "GetChangesAll", "IsInherited": ace['inherited']})
                if object_type in ['domain'] and has_extended_right(ace, "GetChangesInFilteredSet"):
                    res['aces'].append({"PrincipalSID": sid, "RightName": "GetChangesInFilteredSet", "IsInherited": ace['inherited']})
                if object_type in ['user'] and has_extended_right(ace, "UserForceChangePassword"):
                    res['aces'].append({"PrincipalSID": sid, "RightName": "ForceChangePassword", "IsInherited": ace['inherited']})

    return res



def parse_ace(ace_b):
    ace = {
        'type': ace_b['TypeName'],
        'mask': ace_b['Ace']['Mask']['Mask'],
    }

    sid = parse_sid(ace_b['Ace']['Sid'])
    ace['sid'] = sid

    ace['inherited'] = (ace_b['AceFlags'] & 0x10) != 0
    ace['inherit_only_ace'] = (ace_b['AceFlags'] & 0x8) != 0

    if ace['type'] in ['ACCESS_ALLOWED_ACE', 'ACCESS_DENIED_ACE']:
        rights = parse_mask(ace['mask'])
        ace['rights'] = rights
    elif ace['type'] in ['ACCESS_ALLOWED_OBJECT_ACE', 'ACCESS_DENIED_OBJECT_ACE']:
        rights = parse_mask(ace['mask'])
        rights2, guid, i_guid, flags = parse_object_ace(ace['mask'], ace_b['Ace'])
        if guid:
            ace['guid'] = guid
        if i_guid:
            ace['inherited_guid'] = i_guid
        ace['rights'] = rights + rights2
        ace['flags'] = flags

    #if ace['type'] in ['ACCESS_ALLOWED_ACE', 'ACCESS_ALLOWED_OBJECT_ACE']:
    #    ace['type'] = 'ALLOWED'
    #elif ace['type'] in ['ACCESS_DENIED_ACE', 'ACCESS_DENIED_OBJECT_ACE']:
    #    ace['type'] = 'DENIED'

    return ace

def parse_sid(sid_b):
    sid = "S"
    sid += "-" + str(sid_b['Revision'])
    sid += "-" + str(int.from_bytes(sid_b['IdentifierAuthority']['Value'], 'big'))
    for i in range(sid_b['SubAuthorityCount']):
        sid += "-" + str(int.from_bytes(sid_b['SubAuthority'][i*4:i*4+4], 'little'))

    return sid

def parse_mask(mask):
    out = []

    for r, val in rights_dict.items():
        if mask & val == val:
            out.append(r)

    return out

def parse_object_ace(mask, ace):
    out = []
    flags = []
    if (ace['Flags'] & 0x01) != 0:
        flags.append("OBJECT_TYPE_PRESENT")
    if (ace['Flags'] & 0x02) != 0:
        flags.append("INHERITED_OBJECT_TYPE_PRESENT")

    guid = None
    if len(ace['ObjectType']) == 16:
        guid = calculate_guid(ace['ObjectType'])
        #guid = bytes(ace['ObjectType'])

        if guid in extended_rights:
            out.append(extended_rights[guid])
    else:
        guid = 'N/A'

    if len(ace['InheritedObjectType']) == 16:
        i_guid = calculate_guid(ace['InheritedObjectType'])
    else:
        i_guid = 'N/A'

    return out, guid, i_guid, flags

def calculate_guid(b):
    guid = b[0:4][::-1].hex() + '-'
    guid += b[4:6][::-1].hex() + '-'
    guid += b[6:8][::-1].hex() + '-'
    guid += b[8:10].hex() + '-'
    guid += b[10:16].hex()

    return guid

def to_dict(item):
    item_dict = {}
    for attribute in item['attributes']:
        if len(attribute['vals']) == 1:
            item_dict[str(attribute['type'])] = attribute['vals'][0]
        else:
            item_dict[str(attribute['type'])] = attribute['vals']

    return item_dict

def search_name(sid, ldap_obj):
    if sid in sid_name_dict:
        return sid_name_dict[sid]
    
    sc = ldap.SimplePagedResultsControl(size=100)
    res = ldap_obj[0].search(searchBase=ldap_obj[1], searchFilter='(objectSid=%s)' % sid, searchControls=[sc], attributes=['distinguishedName', 'sAMAccountName', 'name', 'objectSid'])
    for entry in res:
        if isinstance(entry, ldapasn1.SearchResultEntry) is not True:
            continue

        entry = to_dict(entry)

        try:
            domain = ".".join([item.split("=", 1)[-1] for item in str(entry['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])

            if 'sAMAccountName' in entry:
                username = str(entry['sAMAccountName'])
            else:
                username = str(entry['name'])
                
            sid2 = LDAP_SID(bytes(entry['objectSid'])).formatCanonical() if 'objectSid' in entry else None

            sid_name_dict[sid2] = '%s\\%s' % (domain, username)
        except Exception as e:
            print("search_name error: %s: %s" % (type(e), str(e)))
            print(entry)
            print(entry.keys())
            #sid_name_dict[sid2] = str(entry['objectCategory'])

 
    if sid in sid_name_dict:
        return sid_name_dict[sid]
    else:
        return sid
