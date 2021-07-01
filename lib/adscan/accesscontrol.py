from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
import ldap3

sid_name_dict = {
    'S-1-5-10': 'Principal Self',
    'S-1-3-0': 'Creator Owner',
    'S-1-1-0': 'Everyone',
    'S-1-5-18': 'Local System',
}

rights_dict = {
    'GenericAll': 983551,
    'GenericWrite': 131112,
    'WriteDACL': 262144,
    'WriteOwner': 524288,
}

extended_rights = {
    '00299570-246d-11d0-a768-00aa006e0529': 'UserForceChangePassword',
    'e362ed86-b728-0842-b27d-2dea7a9df218': 'ReadGMSAPassword',
    'e503b3aa-d05d-44ab-85fa-04fa08251e25': 'ReadLAPSPassword',
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
        rights = parse_object_ace(ace_b['Ace'])
        ace['rights'] = rights

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

def parse_object_ace(ace):
    out = []

    if len(ace['ObjectType']) == 16:
        b = ace['ObjectType']

        guid = b[0:4][::-1].hex() + '-'
        guid += b[4:6][::-1].hex() + '-'
        guid += b[6:8][::-1].hex() + '-'
        guid += b[8:10].hex() + '-'
        guid += b[10:16].hex()

        if guid in extended_rights:
            out.append(extended_rights[guid])

    return out

def search_name(sid, ldap):
    if sid in sid_name_dict:
        return sid_name_dict[sid]

    ldap[0].search(ldap[1], '(objectsid=%s)' % sid, attributes=ldap3.ALL_ATTRIBUTES)
    for entry in ldap[0].entries:
        try:
            domain = ".".join([item.split("=", 1)[-1] for item in str(entry['distinguishedName']).split(',') if item.split("=",1)[0].lower() == "dc"])
            username = str(entry['sAMAccountName'])

            sid_name_dict[sid] = '%s\\%s' % (domain, username)
        except ldap3.core.exceptions.LDAPKeyError:
            sid_name_dict[sid] = str(entry['objectCategory'])

        return sid_name_dict[sid]

    sid_name_dict[sid] = sid
