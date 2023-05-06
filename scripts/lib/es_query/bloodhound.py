import os
import json
import base64
from utils.db import Elasticsearch
from utils.output import Output

from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

BLOODHOUND_VERSION = 5

def export_bloodhound_domains(session, output_dir, output):

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "domain"        }},
            { "match": { "session": session }},
          ],
          "filter": [
          ]
        }
      },
    }

    domains = []
    domain_fqdn_to_name = {}

    filename = os.path.join(output_dir, '%s_bloodhound_domains.txt' % session)
    file = open(filename, 'w')

    # Create output files in dir if non existant

    data = []

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        domains.append({
            'name': source['domain'].upper(),
            'sid': source['sid'],
        })
        domain_fqdn_to_name[source['domain'].upper()] = source['name'].upper()

        object_identifier = source['sid']
        properties = {
            'domain': source['domain'].upper(),
            'name': source['domain'].upper(),
            'distinguishedname': source['dn'].upper(),
            'domainsid': source['sid'],
            'highvalue': True,
            'functionallevel': source['functionallevel'],
        }

        gpo_changes = source['gpo_effect']
        gpo_changes["AffectedComputers"] = source['affected_computers']

        #acl_info = parse_acl(source['sd'], properties['domain'], 'user')
        acl_info = source['aces']

        ace_list = acl_info['aces']
        is_acl_protected = acl_info['is_acl_protected']
        is_deleted = False

        data.append({
            'ObjectIdentifier': object_identifier,
            'Properties': properties,
            'Links': source['links'],
            'Aces': ace_list,
            'GPOChanges': gpo_changes,
            'ChildObjects': source['child_objects'],
            'Trusts': source['trusts'],
            'IsACLProtected': is_acl_protected,
            'IsDeleted': is_deleted,
        })

        c += 1

    meta = {
        "methods": 0,
        "type": "domains",
        "count": c,
        "version": BLOODHOUND_VERSION
    }

    output.append(("Domains", filename, c,  "Domains written"))
    
    file.write(json.dumps({'data': data, 'meta': meta}))

    file.close()

    return domains, domain_fqdn_to_name, output



def export_bloodhound_users(session, output_dir, domains, domain_fqdn_to_name, output):

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "domain_user"        }},
            { "match": { "session": session }},
            #{ "match": { "user": "gmsa3$" }}
          ],
          "filter": [
          ]
        }
      },
    }

    filename = os.path.join(output_dir, '%s_bloodhound_users.txt' % session)
    file = open(filename, 'w')

    # Create output files in dir if non existant

    data = []
    user_info = []
    user_sid = []

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        #if 'Interdomain trust account' in source['tags']:
        #    continue

        if not 'tags' in source:
            source['tags'] = []

        allowed_to_delegate = [] # TODO Not sure why, but sharphound doesn't seem to set this value (msDS-AllowedToDelegateTo)
        object_identifier = source['sid']
        primary_group_sid = "-".join(source['sid'].split('-')[:-1] + [str(source['primary_gid'])])
        spn_targets = source['spns']
        properties = {
            'domain': source['domain'].upper(),
            'name': "%s@%s" % (source['username'].upper(), source['domain'].upper()),
            'distinguishedname': source['dn'].upper(),
            'domainsid': '-'.join(source['sid'].split('-')[:-1]),
            'highvalue': False,
            'unconstraineddelegation': 'Trusted for delegation' in source['tags'],
            'trustedtoauth': 'Trusted to auth for delegation' in source['tags'],
            'passwordnotreqd': 'Password in required' in source['tags'],
            'serviceprincipalnames': spn_targets,
            'admincount': 'adminCount>0' in source['tags'],
        }

        #acl_info = parse_acl(source['sd'], properties['domain'], 'user')
        acl_info = source['aces']

        ace_list = acl_info['aces']
        spn_targets = [] # TODO Not sure why, but sharphound doesn't seem to set this value
        has_sid_history = [] # TODO
        is_deleted = False # TODO
        is_acl_protected = acl_info['is_acl_protected']

        data.append({
            'AllowedToDelegate': allowed_to_delegate,
            'ObjectIdentifier': object_identifier,
            'PrimaryGroupSID': primary_group_sid,
            'Properties': properties,
            'Aces': ace_list,
            'SPNTargets': spn_targets,
            'HasSIDHistory': has_sid_history,
            'IsDeleted': is_deleted,
            'IsACLProtected': is_acl_protected,
        })

        user_info.append({
            'name': source['username'].upper(),
            'domain_fqdn': source['domain'].upper(),
            'domain_name': domain_fqdn_to_name[source['domain'].upper()],
            'sid': source['sid'],
        })
        user_sid.append(source['sid'])

        c += 1

    for domain_info in domains:
        user = {
            "AllowedToDelegate": [],
            "ObjectIdentifier": "%s-S-1-5-20" % domain_info['name'],
            "PrimaryGroupSID": None,
            "Properties": {
                "domain": domain_info['name'],
                "domainsid": domain_info['sid'],
                "name": "NT AUTHORITY@%s" % domain_info['name'],
            },
            "Aces": [],
            "SPNTargets": [],
            "HasSIDHistory": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
        data.append(user)

        c += 1

    meta = {
        "methods": 0,
        "type": "users",
        "count": c,
        "version": BLOODHOUND_VERSION
    }

    output.append(("Users", filename, c,  "Users written"))
    
    file.write(json.dumps({'data': data, 'meta': meta}))

    file.close()

    return user_info, user_sid, output

def get_group_sid(session):
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "domain_group"        }},
            { "match": { "session": session }},
          ],
          "filter": [
          ]
        }
      },
    }

    group_sid = []

    res = Elasticsearch.search(query)
    for item in res:
        source = item['_source']

        group_sid.append(source['sid'])

    return group_sid



def export_bloodhound_groups(session, output_dir, domains, domain_controlers, output):

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "domain_group"        }},
            { "match": { "session": session }},
            #{ "match": { "user": "gmsa3$" }}
          ],
          "filter": [
          ]
        }
      },
    }

    filename = os.path.join(output_dir, '%s_bloodhound_group.txt' % session)
    file = open(filename, 'w')

    # Create output files in dir if non existant

    data = []
    group_sid = []

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        if not 'tags' in source:
            source['tags'] = []

        # Properties
        object_identifier = source['sid']
        if len(source['sid'].split('S-')[-1]) < 30:
            # Is not a complete demain SID
            object_identifier = "%s-%s" % (source['domain'].upper(), object_identifier)
            for domain_info in domains:
                if domain_info['name'].upper() == source['domain'].upper():
                    domain_sid = domain_info['sid']
                    break
        else:
            domain_sid = '-'.join(source['sid'].split('-')[:-1])

        highvalue = False
        for sid_end in ["S-1-5-32-544", "S-1-5-32-550", "S-1-5-32-549", "S-1-5-32-551", "S-1-5-32-548", "-512", "-516", "-519", "-520"]:
            if object_identifier.endswith(sid_end):
                highvalue = True
                break

        domainsid = '-'.join(source['sid'].split('-')[:-1])
        properties = {
            'domain': source['domain'].upper(),
            'name': "%s@%s" % (source['groupname'].upper(), source['domain'].upper()),
            'distinguishedname': source['dn'].upper(),
            'domainsid': domain_sid,
            'highvalue': highvalue,
            'admincount': 'adminCount>0' in source['tags'],
        }
        # Members
        members = source['members']

        #acl_info = parse_acl(source['sd'], properties['domain'], 'user')
        acl_info = source['aces']

        ace_list = acl_info['aces']
        is_deleted = False # TODO
        is_acl_protected = acl_info['is_acl_protected']

        data.append({
            'ObjectIdentifier': object_identifier,
            'Properties': properties,
            'Members': members,
            'Aces': ace_list,
            'IsDeleted': is_deleted,
            'IsACLProtected': is_acl_protected,
        })

        c += 1

    for domain_info in domains:

        group = {
            "IsDeleted": False,
            "IsACLProtected": False,
            "ObjectIdentifier": "%s-S-1-5-9" % domain_info['name'],
            "Properties": {
                "domain": domain_info['name'],
                "domainsid": domain_info['sid'],
                "name": "ENTERPRISE DOMAIN CONTROLLERS@%s" % domain_info['name'],
            },
            "Members": [],
            "Aces": []
        }
        for domain_name, dc_info in domain_controlers.items():
            if domain_name.upper() == domain_info['name'].upper():
                group["Members"].append(dc_info)

        data.append(group)
        c += 1

        # Everyone
        group = {
            "IsDeleted": False,
            "IsACLProtected": False,
            "ObjectIdentifier": "%s-S-1-1-0" % domain_info['name'],
            "Properties": {
                "domain": domain_info['name'],
                "domainsid": domain_info['sid'],
                "name": "EVERYONE@%s" % domain_info['name'],
            },
            "Members": [],
            "Aces": []
        }
        data.append(group)
        c += 1

        # AUTHENTICATED USERS
        group = {
            "IsDeleted": False,
            "IsACLProtected": False,
            "ObjectIdentifier": "%s-S-1-5-11" % domain_info['name'],
            "Properties": {
                "domain": domain_info['name'],
                "domainsid": domain_info['sid'],
                "name": "AUTHENTICATED USERS@%s" % domain_info['name'],
            },
            "Members": [],
            "Aces": []
        }
        data.append(group)
        c += 1

        # INTERACTIVE
        group = {
            "IsDeleted": False,
            "IsACLProtected": False,
            "ObjectIdentifier": "%s-S-1-5-4" % domain_info['name'],
            "Properties": {
                "domain": domain_info['name'],
                "domainsid": domain_info['sid'],
                "name": "INTERACTIVE@%s" % domain_info['name'],
            },
            "Members": [],
            "Aces": []
        }
        data.append(group)
        c+= 1

    meta = {
        "methods": 0,
        "type": "groups",
        "count": c,
        "version": BLOODHOUND_VERSION
    }

    output.append(("Groups", filename, c,  "Groups written"))
    
    file.write(json.dumps({'data': data, 'meta': meta}))

    file.close()

    return output

def export_bloodhound_computers(session, output_dir, user_info, user_sid_list, group_sid_list, output):

    domain_controlers = {}

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "domain_host"        }},
            { "match": { "session": session }},
            #{ "match": { "user": "gmsa3$" }}
          ],
          "filter": [
          ]
        }
      },
    }

    filename = os.path.join(output_dir, '%s_bloodhound_computers.txt' % session)
    file = open(filename, 'w')

    # Create output files in dir if non existant

    data = []

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        if not 'sid' in source:
            # not dumpped from a AD
            continue

        if not 'tags' in source:
            source['tags'] = []

        allowed_to_delegate = [] # TODO Not sure why, but sharphound doesn't seem to set this value (msDS-AllowedToDelegateTo)
        allowed_to_act = [] # TODO 
        object_identifier = source['sid']
        primary_group_sid = "-".join(source['sid'].split('-')[:-1] + [str(source['primary_gid'])])
        spn_targets = source['spns']
        properties = {
            'domain': source['domain'].upper(),
            'name': source['dns'].upper(),
            'distinguishedname': source['dn'].upper(),
            'domainsid': '-'.join(source['sid'].split('-')[:-1]),
            'operatingsystem': source['os'],
            'unconstraineddelegation': 'Trusted for delegation' in source['tags'],
            'trustedtoauth': 'Trusted to auth for delegation' in source['tags'],
            'serviceprincipalnames': spn_targets,
        }

        #acl_info = parse_acl(source['sd'], properties['domain'], 'user')
        acl_info = source['aces']

        ace_list = acl_info['aces']
        spn_targets = [] # TODO Not sure why, but sharphound doesn't seem to set this value
        has_sid_history = [] # TODO
        is_deleted = False # TODO
        is_acl_protected = acl_info['is_acl_protected']

        if 'Server trust account' in source['tags']:
            if source['domain'].upper() in domain_controlers:
                domain_controlers[source['domain'].upper()].append({
                    'ObjectIdentifier': source['sid'],
                    'ObjectType': 'Computer',
                })
            else:
                domain_controlers[source['domain'].upper()] = [{
                    'ObjectIdentifier': source['sid'],
                    'ObjectType': 'Computer',
                }]

        computer_info = {
            'AllowedToDelegate': allowed_to_delegate,
            'AllowedToAct': allowed_to_act,
            'ObjectIdentifier': object_identifier,
            'PrimaryGroupSID': primary_group_sid,
            'Properties': properties,
            'Aces': ace_list,
            'SPNTargets': spn_targets,
            'HasSIDHistory': has_sid_history,
            'IsDeleted': is_deleted,
            'IsACLProtected': is_acl_protected,
        }

        for admin_group, group_name in [("Administrators", "LocalAdmins"), ("Remote Desktop Users", "RemoteDesktopUsers"), ("Distributed COM Users", "DcomUsers"), ("Remote Management Users", "PSRemoteUsers")]:
            if admin_group in source:
                # SID in the list, resolve
                result = []
                for sid in source[admin_group]:
                    if sid in user_sid_list:
                        object_type = "User"
                    elif sid in group_sid_list:
                        object_type = "Group"
                    else:
                        object_type = "Base"
                    result.append({
                        'ObjectIdentifier': sid,
                        'ObjectType': object_type,
                    })

                computer_info[group_name] = {
                    "Results": result,
                    "Collected": True,
                    "FailureReason": None
                }
            else:
                computer_info[group_name] = {
                    "Results": [],
                    "Collected": False,
                    "FailureReason": None
                }

        # Session
        if "host_sessions" in source:
            # SID in the list, resolve
            result = []
            for user in source["host_sessions"]:
                object_type = "User"
                user_sid = next((item['sid'] for item in user_info if item["name"].upper() == user['username'].upper()), None)

                if user_sid != None:
                    result.append({
                        'ObjectIdentifier': user_sid,
                        'ObjectType': object_type,
                    })

            computer_info["Sessions"] = {
                "Results": result,
                "Collected": True,
                "FailureReason": None
            }
        else:
            computer_info["Sessions"] = {
                "Results": [],
                "Collected": False,
                "FailureReason": None
            }

        # Privileged Session
        if "privileged_sessions" in source:
            # SID in the list, resolve
            result = []
            for user in source["privileged_sessions"]:
                object_type = "User"
                user_sid = next((item['sid'] for item in user_info if item["name"].upper() == user['username'].upper() and item["domain_name"].upper() == user['domain'].upper()), None)

                if user_sid != None:
                    result.append({
                        'ObjectIdentifier': user_sid,
                        'ObjectType': object_type,
                    })

            computer_info["PrivilegedSessions"] = {
                "Results": result,
                "Collected": True,
                "FailureReason": None
            }
        else:
            computer_info["PrivilegedSessions"] = {
                "Results": [],
                "Collected": False,
                "FailureReason": None
            }

        # Registry Sessions
        if "registry_sessions" in source:
            # SID in the list, resolve
            result = []
            for user in source["registry_sessions"]:
                object_type = "User"

                result.append({
                    'ObjectIdentifier': user['sid'],
                    'ObjectType': object_type,
                })

            computer_info["RegistrySessions"] = {
                "Results": result,
                "Collected": True,
                "FailureReason": None
            }
        else:
            computer_info["RegistrySessions"] = {
                "Results": [],
                "Collected": False,
                "FailureReason": None
            }



            """
            "Sessions": {
                "Results": [],
                "Collected": False,
                "FailureReason": None
            },
            "PrivilegedSessions": {
                "Results": [],
                "Collected": False,
                "FailureReason": None
            },
            "RegistrySessions": {
                "Results": [],
                "Collected": False,
                "FailureReason": None
            },
            """

        data.append(computer_info)

        c += 1

    meta = {
        "methods": 0,
        "type": "computers",
        "count": c,
        "version": BLOODHOUND_VERSION
    }

    output.append(("Computers", filename, c,  "Computers written"))
    
    file.write(json.dumps({'data': data, 'meta': meta}))

    file.close()

    return domain_controlers, output


def export_bloodhound_ous(session, output_dir, output):

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "domain_ou"        }},
            { "match": { "session": session }},
          ],
          "filter": [
          ]
        }
      },
    }

    filename = os.path.join(output_dir, '%s_bloodhound_ous.txt' % session)
    file = open(filename, 'w')

    # Create output files in dir if non existant

    data = []

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        object_identifier = source['guid'].upper()
        properties = {
            'domain': source['domain'].upper(),
            'name': "%s@%s" % (source['name'].upper(), source['domain'].upper()),
            'distinguishedname': source['dn'].upper(),
            'domainsid': source['domain_sid'],
        }

        gpo_changes = source['gpo_effect']
        gpo_changes["AffectedComputers"] = source['affected_computers']

        acl_info = source['aces']

        ace_list = acl_info['aces']
        is_acl_protected = acl_info['is_acl_protected']
        is_deleted = False

        data.append({
            'ObjectIdentifier': object_identifier,
            'Properties': properties,
            'Aces': ace_list,
            'GPOChanges': gpo_changes,
            'Links': source['links'],
            'ChildObjects': source['child_objects'],
            'IsACLProtected': is_acl_protected,
            'IsDeleted': is_deleted,
        })

        c += 1

    meta = {
        "methods": 0,
        "type": "ous",
        "count": c,
        "version": BLOODHOUND_VERSION
    }

    output.append(("OUs", filename, c,  "OUs written"))
    
    file.write(json.dumps({'data': data, 'meta': meta}))

    file.close()

    return output

def export_bloodhound_containers(session, output_dir, output):

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "domain_container"        }},
            { "match": { "session": session }},
          ],
          "filter": [
          ]
        }
      },
    }

    filename = os.path.join(output_dir, '%s_bloodhound_containers.txt' % session)
    file = open(filename, 'w')

    # Create output files in dir if non existant

    data = []

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        object_identifier = source['guid'].upper()
        properties = {
            'domain': source['domain'].upper(),
            'name': "%s@%s" % (source['name'].upper(), source['domain'].upper()),
            'distinguishedname': source['dn'].upper(),
            'domainsid': source['domain_sid'],
        }

        acl_info = source['aces']

        ace_list = acl_info['aces']
        is_acl_protected = acl_info['is_acl_protected']
        is_deleted = False

        data.append({
            'ObjectIdentifier': object_identifier,
            'Properties': properties,
            'Aces': ace_list,
            'ChildObjects': source['child_objects'],
            'IsACLProtected': is_acl_protected,
            'IsDeleted': is_deleted,
        })

        c += 1

    meta = {
        "methods": 0,
        "type": "containers",
        "count": c,
        "version": BLOODHOUND_VERSION
    }

    output.append(("Containers", filename, c,  "Containers written"))
    
    file.write(json.dumps({'data': data, 'meta': meta}))

    file.close()

    return output

def export_bloodhound_gpos(session, output_dir, output):

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "domain_gpo"        }},
            { "match": { "session": session }},
          ],
          "filter": [
          ]
        }
      },
    }

    filename = os.path.join(output_dir, '%s_bloodhound_gpos.txt' % session)
    file = open(filename, 'w')

    # Create output files in dir if non existant

    data = []

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        object_identifier = source['guid'].upper()
        properties = {
            'domain': source['domain'].upper(),
            'name': "%s@%s" % (source['name'].upper(), source['domain'].upper()),
            'distinguishedname': source['dn'].upper(),
            'domainsid': source['domain_sid'],
            'gpcpath': source['gpcpath'].upper(),
        }

        acl_info = source['aces']

        ace_list = acl_info['aces']
        is_acl_protected = acl_info['is_acl_protected']
        is_deleted = False

        data.append({
            'ObjectIdentifier': object_identifier,
            'Properties': properties,
            'Aces': ace_list,
            'IsACLProtected': is_acl_protected,
            'IsDeleted': is_deleted,
        })

        c += 1

    meta = {
        "methods": 0,
        "type": "gpos",
        "count": c,
        "version": BLOODHOUND_VERSION
    }

    output.append(("GPOs", filename, c,  "GPOs written"))
    
    file.write(json.dumps({'data': data, 'meta': meta}))

    file.close()

    return output

