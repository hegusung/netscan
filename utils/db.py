import elasticsearch
from elasticsearch import helpers
import sys
import os.path
import json
import queue
import time
import traceback
from datetime import datetime
from multiprocessing import Queue, Manager
from threading import Thread
from dns import resolver
from copy import copy
from utils.utils import check_ip
from utils.config import Config
from utils.output import Output

MAX_BULK = 100

es_ids = {
    'dns': 'dns_{session}_{source}_{query_type}_{target}',
    'port': 'port_{session}_{ip}_{protocol}_{port}',
    'script': 'script_{session}_{ip}_{protocol}_{port}_{name}',
    'http': 'http_{session}_{url}',
    'content': 'content_{session}_{url}_{share}_{path}',
    'database': 'database_{session}_{url}_{account}_{database}_{table}',
    'cred_password': 'cred_password_{session}_{url}_{username}_{password}',
    'cred_hash': 'cred_hash_{session}_{url}_{username}_{format}_{hash}',
    'vuln': 'vuln_{session}_{url}_{name}_{description}',
    'smb_host': 'smb_host_{session}_{domain}_{hostname}',
}

es_mapping = {
    "mappings": {
        "properties": {
            "@timestamp": {
                "type": "date"
            },
            "geoip_loc": {
                "type": "geo_point"
            },
        }
    }
}

class DB:

    @classmethod
    def start_worker(self, nodb):
        self.nodb = nodb

        # Check elasticsearch status
        if not self.nodb:
            if not Elasticsearch.ping():
                print("Unable to connect to the elasticsearch instance")
                sys.exit()

            Elasticsearch.check_index()

        manager = Manager()
        #self.db_queue = manager.Queue(256)
        self.db_queue = manager.Queue()

        self.db_thread = Thread(target=self.db_worker, args=(self.db_queue,))
        self.db_thread.daemon = True
        self.db_thread.start()

        self.session = Config.config.get('Global', 'session')

    @classmethod
    def stop_worker(self):
        self.send(None)
        qsize = self.db_queue.qsize()
        if qsize > 0:
            Output.write('waiting for database thread to end properly... (%d remaining)' % qsize)
        self.db_thread.join()
        if qsize > 0:
            Output.write('done')

    @classmethod
    def send(self, doc):
        if doc != None:
            data = json.dumps(doc)
        else:
            data = None
        self.db_queue.put(data, True, 60)

    @classmethod
    def db_worker(self, db_queue):
        inserts = []
        while True:
            try:
                insert = db_queue.get(True, 5)
                if insert == None:
                    if len(inserts) > 0:
                        Elasticsearch.insert_bulk(inserts)
                        inserts = []
                    break
                insert = json.loads(insert)
                insert['session'] = self.session

                if not insert['doc_type'] in es_ids:
                    continue

                if not self.nodb:
                    # Elasticsearch.insert_document(es_ids[insert['doc_type']].format(**insert), insert)
                    if 'append' in insert:
                        append = insert['append']
                        del insert['append']
                    else:
                        append = None
                    inserts.append((es_ids[insert['doc_type']].format(**insert), insert, append))
                    if len(inserts) >= MAX_BULK:
                        Elasticsearch.insert_bulk(inserts)
                        inserts = []
            except queue.Empty:
                if len(inserts) > 0:
                    Elasticsearch.insert_bulk(inserts)
                    inserts = []
            except BrokenPipeError:
                break
            except Exception as e:
                print('%s: %s' % (type(e), e))

    @classmethod
    def insert_dns(self, dns_doc):
        dns_doc['doc_type'] = 'dns'
        dns_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        dns_doc = check_entry(dns_doc, ['source', 'query_type', 'target'], [])
        if dns_doc['query_type'] in ['A']:
            dns_doc['ip'] = dns_doc['target']
            dns_doc['fqdn'] = dns_doc['source']
        if dns_doc['query_type'] in ['PTR']:
            dns_doc['fqdn'] = dns_doc['target']
            dns_doc['ip'] = dns_doc['source']

        self.send(dns_doc)

    @classmethod
    def insert_port(self, host_doc):
        host_doc['doc_type'] = 'port'
        host_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        host_doc = check_entry(host_doc, ['hostname'], ['port', 'protocol', 'service', 'subservice', 'version', 'nmap_service', 'nmap_version', 'banner', 'tags'])

        # add protocol
        host_doc['protocol'] = host_doc['protocol'].lower() if 'protocol' in host_doc else 'tcp'
        # make sure port is an int
        if 'port' in host_doc:
            host_doc['port'] = int(host_doc['port'])
        # lower service
        if 'service' in host_doc:
            host_doc['service'] = host_doc['service'].lower()

        if 'service_info' in host_doc:
            for key, val in host_doc['service_info'].items():
                if type(val) == str:
                    host_doc['service_info'][key] = val.strip()

        to_insert = []
        if check_ip(host_doc['hostname']):
            # 'host' is an IP
            host_doc['ip'] = host_doc['hostname']
            del host_doc['hostname']

            to_insert.append(host_doc)
        else:
            # 'host' is an IP
            ip_list = resolve_hostname(host_doc['hostname'])

            for ip in ip_list:
                # insert hostname in DNS database
                self.insert_dns({
                    'source': host_doc['hostname'],
                    'query_type': 'A',
                    'target': ip,
                })

                host_doc_tmp = copy(host_doc)
                host_doc_tmp['ip'] = ip
                del host_doc_tmp['hostname']

                to_insert.append(host_doc_tmp)

        for doc in to_insert:
            if 'tags' in doc:
                append = {'tags': doc['tags']}
                del doc['tags']
                doc['append'] = append
            self.send(doc)

    @classmethod
    def insert_script(self, script_doc):
        script_doc['doc_type'] = 'script'
        script_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        script_doc = check_entry(script_doc, ['hostname', 'port', 'nmap_service', 'name', 'output'], [])

        # add protocol
        script_doc['protocol'] = script_doc['protocol'].lower() if 'protocol' in script_doc else 'tcp'
        # make sure port is an int
        if 'port' in script_doc:
            script_doc['port'] = int(script_doc['port'])

        to_insert = []
        if check_ip(script_doc['hostname']):
            # 'script' is an IP
            script_doc['ip'] = script_doc['hostname']
            del script_doc['hostname']

            to_insert.append(script_doc)
        else:
            # 'script' is an IP
            ip_list = resolve_hostname(script_doc['hostname'])

            for ip in ip_list:
                # insert hostname in DNS database
                self.insert_dns({
                    'source': script_doc['hostname'],
                    'query_type': 'A',
                    'target': ip,
                })

                script_doc_tmp = copy(script_doc)
                script_doc_tmp['ip'] = ip
                del script_doc_tmp['hostname']

                to_insert.append(script_doc_tmp)

        for doc in to_insert:
            if 'tags' in doc:
                append = {'tags': doc['tags']}
                del doc['tags']
                doc['append'] = append
            self.send(doc)

    @classmethod
    def insert_http_url(self, http_doc):
        http_doc['doc_type'] = 'http'
        http_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        http_doc = check_entry(http_doc, ['hostname', 'port', 'service', 'url', 'http'], [])

        # add protocol
        http_doc['protocol'] = http_doc['protocol'].lower() if 'protocol' in http_doc else 'tcp'
        # make sure port is an int
        if 'port' in http_doc:
            http_doc['port'] = int(http_doc['port'])

        to_insert = []
        if check_ip(http_doc['hostname']):
            # 'http' is an IP
            http_doc['ip'] = http_doc['hostname']
            del http_doc['hostname']

            to_insert.append(http_doc)
        else:
            # 'http' is an IP
            ip_list = resolve_hostname(http_doc['hostname'])

            for ip in ip_list:
                # insert hostname in DNS database
                self.insert_dns({
                    'source': http_doc['hostname'],
                    'query_type': 'A',
                    'target': ip,
                })

                http_doc_tmp = copy(http_doc)
                http_doc_tmp['ip'] = ip
                del http_doc_tmp['hostname']

                to_insert.append(http_doc_tmp)

        for doc in to_insert:
            if 'tags' in doc:
                append = {'tags': doc['tags']}
                del doc['tags']
                doc['append'] = append
            self.send(doc)

    @classmethod
    def insert_content(self, content_doc):
        content_doc['doc_type'] = 'content'
        content_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        content_doc = check_entry(content_doc, ['url', 'path', 'share', 'service'], ['size', 'access'])

        content_doc['service'] = content_doc['service'].lower()

        path = content_doc['path']
        if path.endswith('/'):
            path = path[:-1]
            content_doc['type'] = 'folder'
        else:
            content_doc['type'] = 'file'

        content_doc['directory'] = os.path.dirname(path)
        content_doc['name'] = os.path.basename(path)

        if content_doc['type'] == 'file':
            if '.' in content_doc['name']:
                content_doc['ext'] = content_doc['name'].split('.')[-1].lower()

        if not 'access' in content_doc:
            pass
        else:
            access = []
            for a in content_doc['access']:
                access.append(a.lower())
            content_doc['access'] = access

        to_insert = []
        if check_ip(content_doc['hostname']):
            # 'host' is an IP
            content_doc['ip'] = content_doc['hostname']
            del content_doc['hostname']

            to_insert.append(content_doc)
        else:
            # 'host' is an IP
            ip_list = resolve_hostname(content_doc['hostname'])

            for ip in ip_list:
                # insert hostname in DNS database
                self.insert_dns({
                    'source': content_doc['hostname'],
                    'query_type': 'A',
                    'target': ip,
                })

                content_doc_tmp = copy(content_doc)
                content_doc_tmp['ip'] = ip
                del content_doc_tmp['hostname']

                to_insert.append(content_doc_tmp)

        for doc in to_insert:
            if 'tags' in doc:
                append = {'tags': doc['tags']}
                del doc['tags']
                doc['append'] = append
            self.send(doc)

    @classmethod
    def insert_database(self, database_doc):
        database_doc['doc_type'] = 'database'
        database_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        database_doc = check_entry(database_doc, ['url', 'service', 'database', 'table'], ['account'])

        database_doc['service'] = database_doc['service'].lower()

        if not 'account' in database_doc:
            database_doc['account'] = 'unknown'

        to_insert = []
        if check_ip(database_doc['hostname']):
            # 'host' is an IP
            database_doc['ip'] = database_doc['hostname']
            del database_doc['hostname']

            to_insert.append(database_doc)
        else:
            # 'host' is an IP
            ip_list = resolve_hostname(database_doc['hostname'])

            for ip in ip_list:
                # insert hostname in DNS database
                self.insert_dns({
                    'source': database_doc['hostname'],
                    'query_type': 'A',
                    'target': ip,
                })

                database_doc_tmp = copy(database_doc)
                database_doc_tmp['ip'] = ip
                del database_doc_tmp['hostname']

                to_insert.append(database_doc_tmp)

        for doc in to_insert:
            if 'tags' in doc:
                append = {'tags': doc['tags']}
                del doc['tags']
                doc['append'] = append
            self.send(doc)

    @classmethod
    def insert_credential(self, credential_doc):
        if 'password' in credential_doc:
            credential_doc['doc_type'] = 'cred_password'
        elif 'hash' in credential_doc:
            credential_doc['doc_type'] = 'cred_hash'
        else:
            return
        credential_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        credential_doc = check_entry(credential_doc, ['url', 'service', 'username'], ['password', 'format', 'hash'])

        credential_doc['service'] = credential_doc['service'].lower()

        to_insert = []
        if check_ip(credential_doc['hostname']):
            # 'host' is an IP
            credential_doc['ip'] = credential_doc['hostname']
            del credential_doc['hostname']

            to_insert.append(credential_doc)
        else:
            # 'host' is an IP
            ip_list = resolve_hostname(credential_doc['hostname'])

            for ip in ip_list:
                # insert hostname in DNS credential
                self.insert_dns({
                    'source': credential_doc['hostname'],
                    'query_type': 'A',
                    'target': ip,
                })

                credential_doc_tmp = copy(credential_doc)
                credential_doc_tmp['ip'] = ip
                del credential_doc_tmp['hostname']

                to_insert.append(credential_doc_tmp)

        for doc in to_insert:
            if 'tags' in doc:
                append = {'tags': doc['tags']}
                del doc['tags']
                doc['append'] = append
            self.send(doc)

    @classmethod
    def insert_vulnerability(self, vulnerability_doc):
        vulnerability_doc['doc_type'] = 'vuln'
        vulnerability_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        vulnerability_doc = check_entry(vulnerability_doc, ['url', 'service', 'name', 'description'], [])

        vulnerability_doc['service'] = vulnerability_doc['service'].lower()

        to_insert = []
        if check_ip(vulnerability_doc['hostname']):
            # 'host' is an IP
            vulnerability_doc['ip'] = vulnerability_doc['hostname']
            del vulnerability_doc['hostname']

            to_insert.append(vulnerability_doc)
        else:
            # 'host' is an IP
            ip_list = resolve_hostname(vulnerability_doc['hostname'])

            for ip in ip_list:
                # insert hostname in DNS vulnerability
                self.insert_dns({
                    'source': vulnerability_doc['hostname'],
                    'query_type': 'A',
                    'target': ip,
                })

                vulnerability_doc_tmp = copy(vulnerability_doc)
                vulnerability_doc_tmp['ip'] = ip
                del vulnerability_doc_tmp['hostname']

                to_insert.append(vulnerability_doc_tmp)

        for doc in to_insert:
            if 'tags' in doc:
                append = {'tags': doc['tags']}
                del doc['tags']
                doc['append'] = append
            self.send(doc)

    @classmethod
    def insert_smb_host(self, host_doc):
        host_doc['doc_type'] = 'smb_host'
        host_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        host_doc = check_entry(host_doc, ['domain', 'hostname', 'os'], ['hostname_ip'])

        host_doc['domain'] = host_doc['domain'].lower()

        if len(host_doc['hostname']) == 0:
            if 'hostname_ip' in host_doc:
                host_doc['hostname'] = host_doc['hostname_ip']
        else:
            host_doc['hostname'] = host_doc['hostname'].lower()

        if 'hostname_ip' in host_doc:
            if check_ip(host_doc['hostname_ip']):
                # 'host' is an IP
                host_doc['ip'] = [host_doc['hostname_ip']]
                del host_doc['hostname_ip']
            else:
                # 'host' is a hostname
                ip_list = resolve_hostname(host_doc['hostname_ip'])
                host_doc['ip'] = [ip_list]
                del host_doc['hostname_ip']
        else:
            # lets try to resolve from hostname + domain
            if '.' in host_doc['domain'] and len(host_doc['hostname']) != 0:
                hostname = '%s.%s' % (host_doc['hostname'], host_doc['domain'])
                ip_list = resolve_hostname(hostname)
                if len(ip_list) != 0:
                    host_doc['ip'] = [ip_list]

        self.send(host_doc)


def check_entry(entry, required_list, optional_list):
    for required in required_list:
        if not required in entry:
            raise Exception('Unable to add entry in database: %s is not in %s' % (required, entry))

    for optional in optional_list:
        if not optional in entry:
            pass

    # Remove all trailing characters
    for key in entry:
        if type(entry[key]) == str:
            entry[key] = entry[key].strip()

    # Format entry so they are the same
    if not 'tags' in entry:
        entry['tags'] = []

    return entry

class Elasticsearch(object):

    elasticsearch_instance = None

    @classmethod
    def get_es_instance(self):
        if self.elasticsearch_instance == None:
            es_ip = Config.config.get('Elasticsearch', 'host')
            es_port = int(Config.config.get('Elasticsearch', 'port'))
            es_index = Config.config.get('Elasticsearch', 'index').lower()

            self.elasticsearch_instance = (elasticsearch.Elasticsearch(['http://%s:%d' % (es_ip, es_port)], max_retries=5, retry_on_timeout=True), es_index)

        return self.elasticsearch_instance

    @classmethod
    def ping(self):
        es = self.get_es_instance()
        return es[0].ping()

    @classmethod
    def check_index(self):
        # Create index with correct mapping if it doesn't exist
        es = self.get_es_instance()
        if not es[0].indices.exists(index=es[1]):
            print('Elasticsearch index doesn\'t exist, creating it')

            es[0].indices.create(
                index=es[1],
                body=es_mapping,
                ignore=400 # ignore 400 already exists code
            )

    @classmethod
    def search(self, doc):
        try:
            es = self.get_es_instance()

            res = helpers.scan(es[0], index=es[1], query=doc)

            return res
        except elasticsearch.exceptions.ConnectionError:
            print("Elasticsearch: Unable to connect to elasticsearch instance")

    @classmethod
    def insert_document(self, id, doc):
        try:
            es = self.get_es_instance()

            """
            if "append" in doc:
                append = doc["append"]
                del doc["append"]
            else:
                append = None
            """

            body={
                "doc": doc,
                'doc_as_upsert':True,
            }
            res = es[0].update(index=es[1],
                id=id,
                body=body,
            )

            """
            if append != None:
                for key in append:
                    if type(append[key]) != list:
                        append[key] = list(append[key])
                    for value in append[key]:
                        script = {
                            "params": {
                                "value": value,
                            },
                            "source": "if(ctx._source.%s != null) { ctx._source.%s.contains(params.value) ? (ctx.op = \"none\") : ctx._source.%s.add(params.value); } else { ctx._source.%s = [ params.value ]; }" % (key, key, key, key),
                        }

                        self.insert_script(id, script)
            """

        except elasticsearch.exceptions.ConnectionError:
            print("Elasticsearch: Unable to connect to elasticsearch instance")

    @classmethod
    def insert_bulk(self, inserts):
        try:
            es = self.get_es_instance()

            body = []
            scripts = []
            for insert in inserts:
                # body
                b = {
                    '_op_type': 'update',
                    '_index': es[1],
                    '_id': insert[0],
                    'doc': insert[1],
                    'doc_as_upsert': True,
                }

                # script
                append = insert[2]
                b_s = {
                    '_op_type': 'update',
                    '_index': es[1],
                    '_id': insert[0],
                }

                if append != None:
                    script = {
                        "params": {},
                        "source": "",
                    }

                    for key in append:
                        if type(append[key]) != list:
                            append[key] = list(append[key])
                        if len(append[key]) == 0:
                            continue

                        script['params'][key] = append[key]
                        s = """for (item in params.%s) {
    if(ctx._source.%s != null) {
        if (!ctx._source.%s.contains(item)) { ctx._source.%s.add(item) }
    }
    else {
        ctx._source.%s = [ item ]
    }
}
""" % (key, key, key, key, key)
                        script['source'] += s

                    b_s['script'] = script

                    if len(script['params'].keys()) != 0:
                        scripts.append(b_s)

                body.append(b)

            helpers.bulk(es[0], body, index=es[1])
            if len(scripts) != 0:
                helpers.bulk(es[0], scripts, index=es[1])

        except elasticsearch.exceptions.ConnectionError:
            print("Elasticsearch: Unable to connect to elasticsearch instance")
        except Exception as e:
            print('%s: %s\n%s' % (type(e), e, traceback.format_exc()))


    @classmethod
    def insert_script(self, id, script):
        try:
            es = self.get_es_instance()

            res = es[0].update(index=es[1],
                id=id,
                body={
                    "script": script,
                },
            )
        except elasticsearch.exceptions.ConnectionError:
            print("Elasticsearch: Unable to connect to elasticsearch instance")

def resolve_hostname(hostname):

    ip_results = []

    try:
        ip_results = resolver.query(hostname, "A")
    except resolver.NXDOMAIN:
        pass
    except resolver.NoAnswer:
        pass
    except resolver.NoNameservers:
        pass
    except Timeout:
        pass

    for ip in ip_results:
        ip = str(ip)

    return [str(ip) for ip in ip_results]

