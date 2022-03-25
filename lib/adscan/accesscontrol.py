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
}

object_rights_dict = {
    'ControlAccess': 256,
    'CreateChild': 1,
    'DeleteChild': 2,
    'ReadProperty': 16,
    'Self': 8,
    'WriteProperty': 32,
}

extended_rights = {
    '00299570-246d-11d0-a768-00aa006e0529': 'UserForceChangePassword',
    'e362ed86-b728-0842-b27d-2dea7a9df218': 'ReadGMSAPassword',
    'e503b3aa-d05d-44ab-85fa-04fa08251e25': 'ReadLAPSPassword',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'property:servicePrincipalName',
    'e48d0154-bcf8-11d1-8702-00c04fb96050': 'propertySet:PublicInformation',
    '0e10c968-78fb-11d2-90d4-00c04f79dc55': 'Certificate-Enrollment',
}

def parse_accesscontrol(security_descriptor, ldap):
    a = SR_SECURITY_DESCRIPTOR()
    a.fromString(security_descriptor)

    for ace_b in a['Dacl'].aces:
        ace = parse_ace(ace_b)

        name = search_name(ace['sid'], ldap)
        ace['name'] = name

        yield ace

def parse_ace(ace_b):
    ace = {
        'type': ace_b['TypeName'],
        'mask': ace_b['Ace']['Mask']['Mask'],
    }

    sid = parse_sid(ace_b['Ace']['Sid'])
    ace['sid'] = sid

    if ace['type'] in ['ACCESS_ALLOWED_ACE', 'ACCESS_DENIED_ACE']:
        rights = parse_mask(ace['mask'])
        ace['rights'] = rights
    elif ace['type'] in ['ACCESS_ALLOWED_OBJECT_ACE', 'ACCESS_DENIED_OBJECT_ACE']:
        rights, guid = parse_object_ace(ace['mask'], ace_b['Ace'])
        ace['rights'] = rights
        if guid:
            ace['guid'] = guid

    if ace['type'] in ['ACCESS_ALLOWED_ACE', 'ACCESS_ALLOWED_OBJECT_ACE']:
        ace['type'] = 'ALLOWED'
    elif ace['type'] in ['ACCESS_DENIED_ACE', 'ACCESS_DENIED_OBJECT_ACE']:
        ace['type'] = 'DENIED'

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

def parse_object_mask(mask):
    out = []

    for r, val in object_rights_dict.items():
        if mask & val == val:
            out.append(r)

    return out

def parse_object_ace(mask, ace):
    out = parse_object_mask(mask)

    guid = None
    if len(ace['ObjectType']) == 16:
        guid = calculate_guid(ace['ObjectType'])
        #guid = bytes(ace['ObjectType'])

        if guid in extended_rights:
            out.append(extended_rights[guid])
            guid = None
    else:
        guid = 'N/A'

    return out, guid

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
