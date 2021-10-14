import os
import json
import os.path
from tqdm import tqdm

from utils.db import DB
from utils.db import Elasticsearch
from utils.output import Output

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
    'rmi': [{'service': 'rmi'}],
    'winrm': [{'port': 5985}, {'port': 5986}],
    'x11': [{'port': 6000}],
    'docker': [{'port': 2375}, {'port': 2376}],
}

service_nmap_translate = {
    'netbios-ssn': 'smb',
    'microsoft-ds': 'smb',
    'ms-sql-s': 'mssql',
    'domain': 'dns',
    'mongodb': 'mongo',
    'rpcbind': 'rpc',
    'java-rmi': 'rmi',
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
            { "match": { "doc_type":   "ip"        }},
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

        ip_file.write('%s\n' % source['ip'])

    # get ports
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
    os.system('sort {0} | uniq > {0}_tmp; mv {0}_tmp {0}'.format(ip_filename))
    count = 0
    for _ in open(ip_filename):
        count += 1
    print("%s: %s   %d ips written" % ("ip".ljust(12), ip_filename.ljust(40), count))

    ip_port_file.close()
    # Make files unique
    os.system('sort {0} | uniq > {0}_tmp; mv {0}_tmp {0}'.format(ip_port_filename))
    count = 0
    for _ in open(ip_port_filename):
        count += 1
    print("%s: %s   %d ports written" % ("ip:port".ljust(12), ip_port_filename.ljust(40), count))

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

    url_file.close()
    # Make files unique
    os.system('sort {0} | uniq > {0}_tmp; mv {0}_tmp {0}'.format(url_filename))
    count = 0
    for _ in open(url_filename):
        count += 1
    print("%s: %s   %d urls written" % ("urls".ljust(12), url_filename.ljust(40), count))

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
            { "match": { "session": session }}
          ],
          "filter": [
          ]
        }
      },
    }

    # Create output files in dir if non existant
    nb_documents = Elasticsearch.count(query)

    pg = tqdm(total=nb_documents, mininterval=1, leave=False)

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

    if not os.path.exists(input_file):
        print('The input file must exist')
        return
    
    Output.write("Counting the number of documents....")

    f = open(input_file)
    c = 0
    for line in f:
        c += 1
    f.close()

    Output.write("%d documents to insert in elasticsearch session %s" % (c, session))

    pg = tqdm(total=c, mininterval=1, leave=False)

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
