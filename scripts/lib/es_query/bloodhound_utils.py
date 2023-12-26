from utils.db import Elasticsearch

doc_type_dict = {
    'domain_ou': 'OU',
    'domain_container': 'Container',
    'domain_host': 'Computer',
    'domain_user': 'User',
    'domain_group': 'Group',
}

def get_child_objects(session, dn):
    dn = dn.replace('{', '\\{')
    dn = dn.replace('}', '\\}')

    query = {
      "query": {
        "bool": {
          "must": [
            {
              "match": {"session.keyword": session}
            },
            {
              "regexp": {
                "dn.keyword": {
                  "value": "[^,]+=[^,]+,%s" % dn,
                  "flags": "ALL",
                  "case_insensitive": True
                }
              }
            }
            ], 
            "filter": []
        }
      }
    }

    child_objects = []

    res = Elasticsearch.search(query)
    for item in res:
        source = item['_source']

        try:
            child_type = doc_type_dict[source['doc_type']]
        except KeyError:
            child_type = 'Base'

        if 'sid' in source:
            child_objects.append({
                'ObjectIdentifier': source['sid'],
                'ObjectType': child_type,
            })
        elif 'guid' in source:
            child_objects.append({
                'ObjectIdentifier': source['guid'].upper(),
                'ObjectType': child_type,
            })

    return child_objects

def get_affected_computers(session, dn, domain_sid):
    dn = dn.replace('{', '\\{')
    dn = dn.replace('}', '\\}')

    query = {
      "query": {
        "bool": {
          "must": [
            {
              "match": {"session.keyword": session},
              "match": {"doc_type.keyword": 'domain_host'}
            },
            {
              "regexp": {
                "dn.keyword": {
                  "value": "[^,]+=[^,]+,%s" % dn,
                  "flags": "ALL",
                  "case_insensitive": True
                }
              }
            }
            ], 
            "filter": []
        }
      }
    }

    computer_objects = []

    res = Elasticsearch.search(query)
    for item in res:
        source = item['_source']

        computer_type = doc_type_dict[source['doc_type']]

        if computer_type in ['Computer']:
            if source['sid'].startswith(domain_sid):
                computer_objects.append({
                    'ObjectIdentifier': source['sid'],
                    'ObjectType': computer_type,
                })

    return computer_objects

sid_type_dict = {
    'S-1-0-0': 'Group',
    'S-1-1-0': 'Group',
    'S-1-2-0': 'Group',
    'S-1-2-1': 'Group',
    'S-1-3-0': 'User',
    'S-1-3-1': 'User',
    'S-1-3-4': 'User',
    'S-1-5-7': 'User', 
    'S-1-5-11': 'Group',
    'S-1-5-18': 'User',
}

def process_aces(session, aces):

    for ace in aces:
        sid = "S-1-" + ace['PrincipalSID'].split("S-1-")[-1]

        if not sid in sid_type_dict:
            query = {
              "query": {
                "bool": {
                  "must": [
                    { "match": {"session.keyword": session}, },
                    { "match": {"sid.keyword": sid} }
                  ],
                  "filter": []
                }
              }
            }

            res = Elasticsearch.search(query)
            res = list(res)
            if len(res) == 0:
                object_type = "Base"
            else:
                source = res[0]['_source']
                object_type = doc_type_dict[source['doc_type']]

            sid_type_dict[sid] = object_type

        else:
            object_type = sid_type_dict[sid]

        ace["PrincipalType"] = object_type

    return aces

dn_dict = {}

def resolve_sid_from_dn(session, domain, members):

    output = []

    to_process = []
    for dn in members:
        if not dn.startswith('CN=S-1-'):
            if not dn in dn_dict:
                to_process.append(dn)
            else:
                output.append(dn_dict[dn])
        else:
            sid = dn[3:].split(',')[0]
            if sid in sid_type_dict:
                output.append({
                    'ObjectIdentifier': '%s-%s' % (domain, sid),
                    'ObjectType': sid_type_dict[sid],
                })

    if len(to_process) != 0:
        query = {
          "query": {
            "bool": {
              "must": [
                { "match": {"session.keyword": session}, },
              ],
              "filter": {
                  "terms": {
                      "dn.keyword": to_process,
                  }
               }
            }
          }
        }

        res = Elasticsearch.search(query)
        for item in res:
            source = item['_source']
            object_type = doc_type_dict[source['doc_type']]
            sid = source['sid']

            dn_dict[source['dn']] = {"ObjectIdentifier": sid, "ObjectType": object_type}

            output.append(dn_dict[source['dn']])

            to_process.remove(source['dn'])

        for dn in to_process:
            sid = dn
            object_type = "Base"

            dn_dict[dn] = {"ObjectIdentifier": sid, "ObjectType": object_type}

            output.append(dn_dict[dn])

    return output

def get_object_from_name(session, name):
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": {"session.keyword": session}, },
            { "match": {"hostname.keyword": name} }
          ],
          "filter": []
        }
      }
    }

    res = Elasticsearch.search(query)
    res = list(res)
    if len(res) == 0:
        return None
    else:
        source = res[0]['_source']
        object_type = doc_type_dict[source['doc_type']]

        return {
            "ObjectIdentifier": source['sid'],
            "ObjectType": object_type,
        }

sid_dict = {}
def resolve_sid(session, sid_list):

    output = []

    to_process = []
    for sid in sid_list:
        if not sid in sid_dict:
            to_process.append(sid)
        else:
            output.append(sid_dict[sid])

    if len(to_process) != 0:
        query = {
          "query": {
            "bool": {
              "must": [
                { "match": {"session.keyword": session}, },
              ],
              "filter": {
                  "terms": {
                      "sid.keyword": to_process,
                  }
               }
            }
          }
        }

        res = Elasticsearch.search(query)
        for item in res:
            source = item['_source']
            object_type = doc_type_dict[source['doc_type']]
            sid = source['sid']

            sid_dict[sid] = {"ObjectIdentifier": sid, "ObjectType": object_type}

            output.append(sid_dict[source['sid']])

            to_process.remove(source['sid'])

        for sid in to_process:
            object_type = "Base"

            sid_dict[sid] = {"ObjectIdentifier": sid, "ObjectType": object_type}

            output.append(sid_dict[sid])

    return output

