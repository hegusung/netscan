import os
import json
import os.path
from tqdm import tqdm
from colorama import init, Fore, Style, Back

from utils.db import DB
from utils.db import Elasticsearch
from utils.output import Output
from lib.es_query.bloodhound import *
from lib.es_query.bloodhound_utils import *

#from utils.utils import open

output = []

service_filters = {
    'http': [{'service': 'http'}, {'port': 80}, {'port': 443}, {'port': 8000}, {'port': 8080}],
    'smb': [{'service': 'smb', 'port': 445}],
    'ldap': [{'service': 'ldap'}, {'port': 389}, {'port': 636}, {'port': 3268}, {'port': 3269}],
    # Administration
    'ssh': [{'service': 'ssh'}, {'port': 22}],
    'telnet': [{'service': 'telnet'}, {'port': 23}],
    # Remote desktop
    'rdp': [{'service': 'rdp'}, {'port': 3389}],
    'vnc': [{'service': 'vnc'}, {'port': 5900}, {'port': 5901}],
    # File sharing
    'ftp': [{'service': 'ftp'}, {'port': 21}],
    'rsync': [{'service': 'rsync'}, {'port': 873}],
    'rpc': [{'service': 'rpc'}, {'port': 111}],
    # Databases
    'mysql': [{'service': 'mysql'}, {'port': 3306}],
    'mssql': [{'service': 'mssql'}, {'port': 1433}],
    'mongo': [{'service': 'mongo'}, {'port': 27017}],
    'postgresql': [{'service': 'postgresql'}, {'port': 5432}],
    'redis': [{'service': 'redis'}, {'port': 6379}],
    'oracle': [{'service': 'oracle'}, {'port': 1521}],
    # Other
    'rmi': [{'service': 'rmi'}],
    'winrm': [{'port': 5985}, {'port': 5986}],
    'x11': [{'port': 6000}],
    'docker': [{'service': 'docker'}, {'port': 2375}, {'port': 2376}],
    'rlogin': [{'port': 513}],
    'rtsp': [{'service': 'rtsp'}, {'port': 554}],
    'jdwp': [{'service': 'jdwp'},],
    'snmp': [{'service': 'snmp'},],
}

service_nmap_translate = {
    'netbios-ssn': 'smb',
    'microsoft-ds': 'smb',
    'ms-sql-s': 'mssql',
    'domain': 'dns',
    'mongodb': 'mongo',
    'rpcbind': 'rpc',
    'java-rmi': 'rmi',
    'oracle-tns': 'oracle',
}


def pprint(output_list):
    init()

    COLUMN_1_LENGTH = 20
    COLUMN_2_LENGTH = 60
    COLUMN_3_LENGTH = 30

    print("|" + "-" * (COLUMN_1_LENGTH + COLUMN_2_LENGTH + COLUMN_3_LENGTH + 2) + "|")
    print(Style.BRIGHT + Back.RED + Fore.WHITE + "|%s|%s|%s|" % ("TYPE".center(COLUMN_1_LENGTH), "FILENAME".center(COLUMN_2_LENGTH), "COUNT".center(COLUMN_3_LENGTH)) + Style.RESET_ALL)
    print("|" + "-" * (COLUMN_1_LENGTH + COLUMN_2_LENGTH + COLUMN_3_LENGTH + 2) + "|")
    
    for log in output_list:
        type, filename, count, text = log

        if filename.startswith('/host/'):
            filename = filename[5:]

        color = Style.BRIGHT + Fore.GREEN if count > 0 else Fore.WHITE

        print((color + "|%s|%s|%s|" + Style.RESET_ALL) % (type.center(COLUMN_1_LENGTH), filename.center(COLUMN_2_LENGTH), " ".join([str(count), text]).center(COLUMN_3_LENGTH)))
        #print("|" + "-" * (COLUMN_1_LENGTH + COLUMN_2_LENGTH + COLUMN_3_LENGTH + 2) + "|")

    print("|" + "-" * (COLUMN_1_LENGTH + COLUMN_2_LENGTH + COLUMN_3_LENGTH + 2) + "|")


def export_ports(session, service, output_dir):
    global output
    output = []

    if not session:
        print('A session must be defined')
        return

    if not os.path.exists(output_dir):
        print('The destination folder must exist')
        return

    if not os.path.isdir(output_dir):
        print('The destination must be a folder')
        return

    export_ip_ports(session, service, output_dir)
    export_undiscovered_services(session, output_dir)

    export_domains(session, output_dir)
    export_domain_controllers(session, output_dir)
    export_domain_hosts(session, output_dir)
    export_domain_enabled_users(session, output_dir)

    export_http_urls(session, output_dir)

    pprint(output)


def export_hashes(session, service, output_dir):
    global output
    output = []

    if not session:
        print('A session must be defined')
        return

    if not os.path.exists(output_dir):
        print('The destination folder must exist')
        return

    if not os.path.isdir(output_dir):
        print('The destination must be a folder')
        return

    export_local_hashes(session, output_dir)
    export_domain_hashes(session, output_dir)

    pprint(output)

def export_ip_ports(session, service, output_dir):
    global output

    # Create output files in dir if non existant
    ip_filename = os.path.join(output_dir, '%s_ips.txt' % session)
    ip_file = open(ip_filename, 'a')
    ip_port_filename = os.path.join(output_dir, '%s_ip_ports.txt' % session)
    ip_port_file = open(ip_port_filename, 'a')

    output_files = {}
    for service_name in service_filters:
        filename = os.path.join(output_dir, '%s_%s.txt' % (session, service_name))
        output_files[service_name] = {'filename': filename, 'file': open(filename, 'a'), 'count': 0}

    # Get Hostnames
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "dns"        }},
            { "match": { "session": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']
        s_service = None

        if source['query_type'] == 'A':
            ip_file.write('%s\n' % source['target'])
        elif source['query_type'] == 'PTR':
            ip_file.write('%s\n' % source['source'])

    # Get IPs up
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "ip"        }},
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']
        s_service = None

        ip_file.write('%s\n' % source['ip'])

    # get ports
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "port"        }},
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }
    if service:
        query['query']['bool']['must'].append({'match': {'service': service}})

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']
        s_service = None

        ip_file.write('%s\n' % source['ip'])
        ip_port_file.write('%s:%d\n' % (source['ip'], source['port']))

        if 'service' in source:
            s_service = source['service']
        elif 'nmap_service' in source:
            s_service = source['nmap_service']
            if s_service in service_nmap_translate:
                s_service = service_nmap_translate[s_service]
            source['service'] = s_service

        for service, filters in service_filters.items():
            for f in filters:
                match = False
                for key, value in f.items():
                    if not key in source:
                        continue
                    if source[key] == value:
                        match = True
                        break

                if match:
                    #print("%s => %s:%d" % (service, source['ip'], source['port']))
                    output_files[service]['file'].write('%s:%d\n' % (source['ip'], source['port']))
                    output_files[service]['count'] += 1
                    break
        c += 1

    ip_file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(ip_filename))
    count = 0
    for _ in open(ip_filename):
        count += 1
    
    output.append(("ip", ip_filename, count,  "ips written"))

    ip_port_file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(ip_port_filename))
    count = 0
    for _ in open(ip_port_filename):
        count += 1
    output.append(("ip:port", ip_port_filename, count, "ports written"))

    for service, f in output_files.items():
        f['file'].close()

        output.append((service, f['filename'], f['count'],  "ports written"))

        # Make files unique
        os.system('sort \'%s\' | uniq > \'%s_tmp\'; mv \'%s_tmp\' \'%s\'' % (f['filename'], f['filename'], f['filename'], f['filename']))


def export_domains(session, output_dir):
    global output

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "port"        }},
            { "match": { "service.keyword":   "smb"        }},
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    filename = os.path.join(output_dir, '%s_domain.txt' % session)
    file = open(filename, 'a')

    # Create output files in dir if non existant

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']
        s_service = None

        if '.' in source['service_info']['domain']:
            file.write('%s\n' % source['service_info']['domain'])
        c += 1

    file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(filename))
    count = 0
    for _ in open(filename):
        count += 1
    
    output.append(("domains", filename, count,  "domains written"))


def export_domain_controllers(session, output_dir):
    global output

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "port"        }},
            { "match": { "service.keyword":   "smb"        }},
            { "match": { "service_info.is_dc" : True }},
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    filename = os.path.join(output_dir, '%s_domain_controller.txt' % session)
    file = open(filename, 'a')

    # Create output files in dir if non existant

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']
        s_service = None

        file.write('%s %s\n' % (source['ip'], source['service_info']['domain']))
        c += 1

    file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(filename))
    count = 0
    for _ in open(filename):
        count += 1
    
    output.append(("dom_ctrls", filename, count,  "domain controllers written"))


def export_undiscovered_services(session, output_dir):
    global output

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "port"        }},
            { "match": { "session.keyword": session }},
          ],
          "must_not": [
              { "exists": { "field": "nmap_service" }},
              { "exists": { "field": "service" }},
          ],
          "filter": [
          ]
        }
      },
    }

    filename = os.path.join(output_dir, '%s_undiscovered_service.txt' % session)
    try:
        os.remove(filename)
    except FileNotFoundError:
        pass
    file = open(filename, 'a')

    # Create output files in dir if non existant

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']
        s_service = None

        file.write('%s:%d\n' % (source['ip'], source['port']))
        c += 1

    file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(filename))
    count = 0
    for _ in open(filename):
        count += 1

    output.append(("undiscovered", filename, count,  "ip:port written"))


def export_http_urls(session, output_dir):

    global output

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "http"        }},
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    url_filename = os.path.join(output_dir, '%s_http_urls.txt' % session)
    url_file = open(url_filename, 'a')

    # Create output files in dir if non existant

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']
        s_service = None

        url_file.write('%s\n' % source['url'])
        c += 1

    url_file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(url_filename))
    count = 0
    for _ in open(url_filename):
        count += 1
      
    output.append(("urls", url_filename, count,  "urls written"))


def export_domain_hashes(session, output_dir):
    global output

    enabled_users = []

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_user"        }},
            { "match": { "session.keyword": session }}
          ],
          "must_not": [
            { "match": { "tags":   "Account disabled"  }},
          ],
          "filter": [
          ]
        }
      },
    }

    res = Elasticsearch.search(query)
    for item in res:
        source = item['_source']

        username = "%s\\%s" % (source['domain'], source['username'])

        enabled_users.append(username)

    # NTLM
        
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_hash"        }},
            { "match": { "format.keyword": "ntlm" }},
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    hashfile_filename = os.path.join(output_dir, '%s_domain_username_ntlm_hash_enabled.txt' % session)
    hashfile_file = open(hashfile_filename, 'a')

    # Create output files in dir if non existant

    res = Elasticsearch.search(query)
    for item in res:
        source = item['_source']

        username = "%s\\%s" % (source['domain'], source['username'])

        if ':' in source['hash']:
            ntlm = source['hash'].split(':')[-1]
        else:
            ntlm = source['hash']

        if username in enabled_users:
            hashfile_file.write('%s\\%s:%s\n' % (source['domain'], source['username'], ntlm))

    hashfile_file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(hashfile_filename))
    count = 0
    for _ in open(hashfile_filename):
        count += 1

    output.append(("Domain hashes", hashfile_filename, count,  "hashes written"))

    # ASREPROASTING

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_hash"        }},
            { "match": { "format.keyword": "krb5asrep" }},
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    hashfile_filename = os.path.join(output_dir, '%s_domain_username_krb5asrep_hash_enabled.txt' % session)
    hashfile_file = open(hashfile_filename, 'a')

    # Create output files in dir if non existant

    res = Elasticsearch.search(query)
    processed = []
    for item in res:
        source = item['_source']

        username = "%s\\%s" % (source['domain'], source['username'])

        if username in enabled_users:
            if not username in processed:
                hashfile_file.write('%s\n' % (source['hash'],))
                processed.append(username)

    hashfile_file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(hashfile_filename))
    count = 0
    for _ in open(hashfile_filename):
        count += 1

    output.append(("krb5asrep", hashfile_filename, count,  "hashes written"))

    # KERBEROASTING

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_hash"        }},
            { "match": { "format.keyword": "krb5tgs" }},
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    hashfile_filename = os.path.join(output_dir, '%s_domain_username_krb5tgs_hash_enabled.txt' % session)
    hashfile_file = open(hashfile_filename, 'a')

    # Create output files in dir if non existant

    res = Elasticsearch.search(query)
    processed = []
    for item in res:
        source = item['_source']

        username = "%s\\%s" % (source['domain'], source['username'])

        if username in enabled_users:
            if not username in processed:
                hashfile_file.write('%s\n' % (source['hash'],))
                processed.append(username)

    hashfile_file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(hashfile_filename))
    count = 0
    for _ in open(hashfile_filename):
        count += 1

    output.append(("krb5tgs", hashfile_filename, count,  "hashes written"))


def export_local_hashes(session, output_dir):
    global output
       
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "cred_hash"        }},
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    # Create output files in dir if non existant

    hash_dict = {}

    res = Elasticsearch.search(query)
    for item in res:
        source = item['_source']

        username = "%s_%s" % (source['url'], source['username'])
        username = username.replace(":", "_")

        if source['format'] == 'ntlm':
            if ':' in source['hash']:
                hash = source['hash'].split(':')[-1]
            else:
                hash = source['hash']
        else:
            hash = source['hash']

        if not source['format'] in hash_dict:
            hash_dict[source['format']] = []

        hash_dict[source['format']].append("%s:%s" % (username, hash))

    for format, hash_list in hash_dict.items():
        hashfile_filename = os.path.join(output_dir, '%s_%s_hashes.txt' % (session, format))
        hashfile_file = open(hashfile_filename, 'a')

        for h in hash_list:
            hashfile_file.write('%s\n' % h)

        hashfile_file.close()

        # Make files unique
        os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(hashfile_filename))
        count = 0
        for _ in open(hashfile_filename):
            count += 1

        output.append((format, hashfile_filename, count,  "hashes written"))

def export_bloodhound(session, output_dir):
    global output
    output = []

    #output.append((format, hashfile_filename, count,  "hashes written"))

    links_dict, links_effect = get_gpos_links(session)

    user_info, user_sid, group_sid = get_user_group_data(session)

    containedby_dict = generate_containedby(session)

    domains, domain_fqdn_to_name, domain_name_to_sid, output = export_bloodhound_domains(session, links_dict, links_effect, output_dir, user_info, user_sid, group_sid, output)

    output = export_bloodhound_containers(session, domain_name_to_sid, output_dir, containedby_dict, output)

    output = export_bloodhound_ous(session, domain_name_to_sid, links_dict, links_effect, output_dir, user_info, user_sid, group_sid, containedby_dict, output)

    output = export_bloodhound_users(session, output_dir, domains, domain_fqdn_to_name, containedby_dict, output)

    output = export_bloodhound_gpos(session, domain_name_to_sid, output_dir, output)

    domain_controlers, output = export_bloodhound_computers(session, output_dir, user_info, user_sid, group_sid, containedby_dict, output)

    output = export_bloodhound_groups(session, output_dir, domains, domain_controlers, containedby_dict, output)

    # ADCS

    output = export_bloodhound_ntauthstores(session, output_dir, domains, containedby_dict, output)
    output = export_bloodhound_rootcas(session, output_dir, domains, containedby_dict, output)
    output = export_bloodhound_aiacas(session, output_dir, domains, containedby_dict, output)
    output, templates = export_bloodhound_certificate_templates(session, output_dir, domains, containedby_dict, output)
    output = export_bloodhound_enrollment_services(session, output_dir, domains, templates, containedby_dict, output)


    pprint(output)

def get_gpos_admins(session):
    links_dict, links_effect = get_gpos_links(session)

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_user"   }},
            { "match": { "session.keyword": session }},
          ],
          "filter": [
          ]
        }
      },
    }

    user_dict = {}

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        if not 'sid' in source:
            continue

        user_dict[source['sid']] = "%s@%s" % (source['username'], source['domain'])

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_group"        }},
            { "match": { "session.keyword": session }},
          ],
          "filter": [
          ]
        }
      },
    }

    group_dict = {}

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        if not 'sid' in source:
            continue

        group_dict[source['sid']] = "%s@%s" % (source['groupname'], source['domain'])

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_host"        }},
            { "match": { "session.keyword": session }},
          ],
          "filter": [
          ]
        }
      },
    }

    computer_dict = {}

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        if not 'sid' in source:
            continue

        computer_dict[source['sid']] = source['dns']

    query = {
      "query": {
        "bool": {
          "must": [
            {
              "bool": {
                "should": [
                  { "match": { "doc_type.keyword": "domain_ou" } },
                  { "match": { "doc_type.keyword": "domain" } }
                ]
              }
            },
            { "match": { "session.keyword": session } }
          ],
          "filter": []
        }
      }
    }

    count = Elasticsearch.count(query)
    Output.write("Processing %d OUs & domains" % count)

    pg = tqdm(total=count, mininterval=1, leave=False, dynamic_ncols=True)

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']
        print("====== %s ======" % source['name'])

        if 'sid' in source:
            sid = source['sid']
        else:
            sid = source['domain_sid']

        affected_computers = list(set([item['ObjectIdentifier'] for item in get_affected_computers(session, source['dn'], sid)]))
        print("Affected computers:")
        for computer in affected_computers:
            if computer in computer_dict:
                print("  > %s" % computer_dict[computer])
            else:
                print("  > %s" % computer)


        print("Links:")
        links = []
        if 'links' in source:
            links = source['links']
        elif 'gplink' in source:
            links = {}
            for l in str(source['gplink']).split(']'):
                if len(l) == 0:
                    continue
                # Remove initial [
                l = l[1:]
                # Take after ://
                l = l.split('://')[-1]
                # Take before ;
                status = l.split(';')[1]
                link = l.split(';')[0]

                # 1 and 3 represent Disabled, Not Enforced and Disabled, Enforced respectively.
                if status in ['1', '3']:
                    continue

                links[link.lower()] = {'IsEnforced': False if status == '0' else True}

            # Get GUID for links
            for link_dn in links:
                if link_dn in links_dict:
                    links[link_dn]['GUID'] = links_dict[link_dn]
                else:
                    links[link_dn]['GUID'] = "Unknown"

            links = list(links.values())

        for link in links:
            print("  > %s" % link)

        print("GPO changes:")

        # Recreate gpo_changes
        gpo_changes = {}
        for sid in OU.privileged_sid_dict:
            gpo_changes[sid] = {}
            for t in ['Memberof', 'Members', 'Localgroup']:
                gpo_changes[sid][t] = []

        for link in links:
            if link['GUID'] in links_effect:

                for effect in links_effect[link['GUID']]['Memberof']:
                    member = effect['member']

                    if not member.startswith('S-'):
                        if '\\' in member:
                            username = member.split('\\')[-1]
                        else:
                            username = member

                        # TODO: domain check
                        member = next((item['sid'] for item in user_info if item["name"].upper() == username.upper()), None)

                    if member != None:
                        gpo_changes[effect['group']]['Memberof'].append({
                            'ObjectIdentifier': effect['member'], 
                        }) 

                for effect in links_effect[link['GUID']]['Members']:
                    for member in effect['members']:

                        if not member.startswith('S-'):
                            if '\\' in member:
                                username = member.split('\\')[-1]
                            else:
                                username = member

                            # TODO: domain check
                            member = next((item['sid'] for item in user_info if item["name"].upper() == username.upper()), None)

                        if member != None:
                            gpo_changes[effect['group']]['Members'].append({
                                'ObjectIdentifier': member, 
                            }) 

                for effect in links_effect[link['GUID']]['Localgroup']:
                    if effect['action'] == 'deleteAllUsers':
                        for item in gpo_changes[effect['group']]['Localgroup'][:]:
                            if item['ObjectType'] == 'User':
                                gpo_changes[effect['group']]['Localgroup'].remove(item)

                    elif effect['action'] == 'deleteAllGroups':
                        for item in gpo_changes[effect['group']]['Localgroup'][:]:
                            if item['ObjectType'] == 'Group':
                                gpo_changes[effect['group']]['Localgroup'].remove(item)

                    elif effect['action'] == 'add':
                        member = effect['member']

                        if not member.startswith('S-'):
                            if '\\' in member:
                                username = member.split('\\')[-1]
                            else:
                                username = member

                            # TODO: domain check
                            member = next((item['sid'] for item in user_info if item["name"].upper() == username.upper()), None)

                        if member != None:
                            gpo_changes[effect['group']]['Localgroup'].append({
                                'ObjectIdentifier': member, 
                            })

                    elif effect['action'] == 'delete':
                        member = effect['member']

                        if not member.startswith('S-'):
                            if '\\' in member:
                                username = member.split('\\')[-1]
                            else:
                                username = member

                            # TODO: domain check
                            member = next((item['sid'] for item in user_info if item["name"].upper() == username.upper()), None)

                        if member != None:
                            for item in gpo_changes[effect['group']]['Localgroup']:
                                if item['ObjectIdentifier'] == member:
                                    del gpo_changes[effect['group']]['Localgroup'][item]
            
        gpo_changes = GPO.merge_gpo_effect(gpo_changes)

        for name, items in gpo_changes.items():
            print("  [%s]" % name)
            for item in items:
                item = item['ObjectIdentifier']

                if item in user_dict:
                    item = "User: %s" % user_dict[item]

                if item in group_dict:
                    item = "Group: %s" % group_dict[item]

                print("    > %s" % item)







        print("==================")





def export_domain_hosts(session, output_dir):
       
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_host"        }},
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    # Create output files in dir if non existant

    domain_host_filename = os.path.join(output_dir, '%s_domain_hosts.txt' % session)
    domain_host_file = open(domain_host_filename, 'a')

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        if 'dns' in source:
            domain_host_file.write('%s\n' % source['dns'])
        c += 1

    domain_host_file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(domain_host_filename))
    count = 0
    for _ in open(domain_host_filename):
        count += 1
      
    output.append(("domain_hosts", domain_host_filename, count,  "Domain hosts written"))

def export_domain_enabled_users(session, output_dir):
       
    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type.keyword":   "domain_user"        }},
            { "match": { "session.keyword": session }}
          ],
          "must_not": [
            { "match": { "tags":   "Account disabled"  }},
          ],
          "filter": [
          ]
        }
      },
    }

    # Create output files in dir if non existant

    domain_user_filename = os.path.join(output_dir, '%s_domain_users.txt' % session)
    domain_user_file = open(domain_user_filename, 'a')

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        if 'domain' in source and 'username' in source:
            domain_user_file.write('%s\\%s\n' % (source['domain'], source['username']))
        c += 1

    domain_user_file.close()
    # Make files unique
    os.system('sort \'{0}\' | uniq > \'{0}_tmp\'; mv \'{0}_tmp\' \'{0}\''.format(domain_user_filename))
    count = 0
    for _ in open(domain_user_filename):
        count += 1
      
    output.append(("domain_users", domain_user_filename, count,  "Domain users written"))



def dump(session, output_file):
    if not session:
        print('A session must be defined')
        return

    Output.write("Dumping session %s content to file %s" % (session, output_file))

    f = open(output_file, "w")

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "session.keyword": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    # Create output files in dir if non existant
    nb_documents = Elasticsearch.count(query)

    pg = tqdm(total=nb_documents, mininterval=1, leave=False, dynamic_ncols=True)

    res = Elasticsearch.search(query)
    c = 0
    for item in res:
        source = item['_source']

        f.write('%s\n' % json.dumps(source))
        c += 1

        pg.update(1)

    f.close()

    pg.close()

    Output.write("%d documents dumped to %s" % (c, output_file))


def restore(session, input_file):
    if not session:
        print('A session must be defined')
        return

    #if not os.path.exists(input_file):
    #    print('The input file must exist')
    #    return
    
    Output.write("Counting the number of documents....")

    f = open(input_file)
    c = 0
    for line in f:
        c += 1
    f.close()

    Output.write("%d documents to insert in elasticsearch session %s" % (c, session))

    pg = tqdm(total=c, mininterval=1, leave=False, dynamic_ncols=True)

    f = open(input_file)

    for line in f:
        line = line.strip()

        document = json.loads(line)

        document['session'] = session

        DB.send(document)

        pg.update(1)

    pg.close()
    f.close()

    Output.write("%d documents inserted in elasticsearch" % (c,))

def delete_session(session):

    query = {
      "query": {
        "match": {
            "session.keyword":   session
        }
      },
    }

    res = Elasticsearch.delete_by_query(query)

    print("Deleted %d documents" % res['deleted'])

