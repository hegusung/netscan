import os
import os.path

from utils.db import Elasticsearch

service_filters = {
    'http': [{'service': 'http'}, {'port': 80}, {'port': 443}],
    'smb': [{'service': 'smb', 'port': 445}],
    'ldap': [{'service': 'ldap'}, {'port': 389}],
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
}

service_nmap_translate = {
    'netbios-ssn': 'smb',
    'microsoft-ds': 'smb',
    'ms-sql-s': 'mssql',
    'domain': 'dns',
    'mongodb': 'mongo',
    'rpcbind': 'rpc',
}

def export(session, service, output_dir):
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
    export_http_urls(session, output_dir)

def export_ip_ports(session, service, output_dir):

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "port"        }},
            { "match": { "session": session }}
          ],
          "filter": [
          ]
        }
      },
    }
    if service:
        query['query']['bool']['must'].append({'match': {'service': service}})

    ip_filename = os.path.join(output_dir, '%s_ips.txt' % session)
    ip_file = open(ip_filename, 'a')
    ip_port_filename = os.path.join(output_dir, '%s_ip_ports.txt' % session)
    ip_port_file = open(ip_port_filename, 'a')

    output_files = {}
    for service in service_filters:
        filename = os.path.join(output_dir, '%s_%s.txt' % (session, service))
        output_files[service] = {'filename': filename, 'file': open(filename, 'a'), 'count': 0}

    # Create output files in dir if non existant

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

        if not s_service:
            continue

        for service, filters in service_filters.items():
            for f in filters:
                match = True
                for key, value in f.items():
                    if not key in source:
                        match = False
                        break
                    if not source[key] == value:
                        match = False
                        break

                if match:
                    print("%s => %s:%d" % (service, source['ip'], source['port']))
                    output_files[service]['file'].write('%s:%d\n' % (source['ip'], source['port']))
                    output_files[service]['count'] += 1
                    break
        c += 1
    print(c)

    ip_file.close()
    # Make files unique
    os.system('sort {0} | uniq > {0}_tmp; mv {0}_tmp {0}'.format(ip_filename))

    ip_port_file.close()
    # Make files unique
    os.system('sort {0} | uniq > {0}_tmp; mv {0}_tmp {0}'.format(ip_port_filename))

    for service, f in output_files.items():
        f['file'].close()

        print("%s: %s   %d ports written" % (service.ljust(12), f['filename'].ljust(40), f['count']))

        # Make files unique
        os.system('sort %s | uniq > %s_tmp; mv %s_tmp %s' % (f['filename'], f['filename'], f['filename'], f['filename']))


def export_http_urls(session, output_dir):

    query = {
      "query": {
        "bool": {
          "must": [
            { "match": { "doc_type":   "http"        }},
            { "match": { "session": session }}
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
    print(c)

    url_file.close()
    # Make files unique
    os.system('sort {0} | uniq > {0}_tmp; mv {0}_tmp {0}'.format(url_filename))

