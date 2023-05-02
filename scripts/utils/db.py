import elasticsearch
from elasticsearch import helpers
import sys
import os.path
import json
import queue
import traceback
from datetime import datetime
from multiprocessing import Manager
from threading import Thread
import dns
from dns import resolver
from copy import copy
from utils.utils import check_ip
from utils.config import Config
from utils.output import Output
from utils.utils import normalize_path
import urllib3
urllib3.disable_warnings()

MAX_BULK = 100

es_ids = {
    'ip': 'ip_{session}_{ip}',
    'dns': 'dns_{session}_{source}_{query_type}_{target}',
    'port': 'port_{session}_{ip}_{protocol}_{port}',
    'script': 'script_{session}_{ip}_{protocol}_{port}_{name}',
    'http': 'http_{session}_{url}',
    'content': 'content_{session}_{url}_{account}_{share}_{path}',
    'application': 'application_{session}_{url}_{name}_{version}',
    'database': 'database_{session}_{url}_{account}_{database}_{table}',
    'cred_password': 'cred_password_{session}_{url}_{username}_{password}',
    'cred_hash': 'cred_hash_{session}_{url}_{username}_{format}_{hash}',
    'vuln': 'vuln_{session}_{url}_{name}_{description}',
    'domain': 'domain_domain_{session}_{domain}',
    'domain_container': 'domain_container_{session}_{domain}_{guid}',
    'domain_ou': 'domain_ou_{session}_{domain}_{guid}',
    'domain_gpo': 'domain_gpo_{session}_{domain}_{guid}',
    'domain_host': 'domain_host_{session}_{domain}_{hostname}',
    'domain_user': 'domain_user_{session}_{domain}_{username}',
    'domain_group': 'domain_group_{session}_{domain}_{groupname}',
    'domain_spn': 'domain_spn_{session}_{domain}_{spn}',
    'domain_password': 'domain_password_{session}_{domain}_{username}_{password}',
    'domain_hash': 'domain_hash_{session}_{domain}_{username}_{format}_{hash}',
    'host_linux': 'host_linux_{session}_{ip}',
    'host_linux_pkg': 'host_linux_pkg_{session}_{ip}_{pkg_name}',
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
            "ip": {
                "type": "ip"
            },
            "hash": {
                "type": "text",
                "fields": {
                    "keyword":{
                        "type": "keyword",
                        "ignore_above": 15000
                    }
                }
            },
            "path": {
                "type": "text",
                "fields": {
                    "keyword":{
                        "type": "keyword",
                        "ignore_above": 2000
                    }
                }
            },
            "created_date": {
                "type": "date"
            },
            "last_logon": {
                "type": "date"
            },
            "last_password_change": {
                "type": "date"
            },
        }
    }
}

class DB:

    @classmethod
    def start_worker(self, nodb, session=None, queue_size=10000):
        self.nodb = nodb
        db_enabled = False if Config.config.get('Elasticsearch', 'enabled') in ['false', 'False'] else True
        if self.nodb == False and db_enabled == False:
            self.nodb = True

        self.es_file_storage = Config.config.get('Elasticsearch', 'document_storage_file')
        self.es_file_storage_enabled = False if Config.config.get('Elasticsearch', 'enable_file_storage') in ['false', 'False'] else True
        self.es_file_storage_count = 0

        # Check elasticsearch status
        if not self.nodb:
            if not Elasticsearch.ping():
                Output.error("Elasticsearch: Unable to connect to elasticsearch instance")
                sys.exit()

            Elasticsearch.check_index()

        manager = Manager()

        if queue_size:
            self.db_queue = manager.Queue(queue_size)
        else:
            self.db_queue = manager.Queue()

        self.db_thread = Thread(target=self.db_worker, args=(self.db_queue,))
        self.db_thread.daemon = True
        self.db_thread.start()

        if session:
            self.session = session
        else:
            self.session = Config.config.get('Global', 'session')

    @classmethod
    def stop_worker(self):
        self.send(None)
        qsize = self.db_queue.qsize()
        if qsize > 0:
            Output.minor('waiting for database thread to end properly... (%d remaining)' % qsize)
        self.db_thread.join()
        if qsize > 0:
            Output.minor('done')

        if self.es_file_storage_count > 0:
            if self.es_file_storage_enabled:
                Output.minor('%d Documents has been written to the following file: %s' % (self.es_file_storage_count, self.es_file_storage))
                Output.minor('Please restore the data to an elasticsearch database using: ./es_query.py --restore %s' % (self.es_file_storage,))
            else:
                Output.error('Some documents failed to insert into the database, they have been stored in a file')
                Output.error('%d Documents has been written to the following file: %s' % (self.es_file_storage_count, self.es_file_storage))
                Output.error('Please restore the data to an elasticsearch database using: ./es_query.py --restore %s' % (self.es_file_storage,))


    @classmethod
    def send(self, doc):
        if doc != None:

            # Add generic data
            if 'ip' in doc and 'port' in doc:
                doc['ip_port'] = "%s:%d" % (doc['ip'], doc['port'])

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
                        error = Elasticsearch.insert_bulk(inserts)
                        if error and not self.es_file_storage_enabled:
                            # Backup in the file
                            f = open(normalize_path(self.es_file_storage), 'a')
                            for insert in inserts:
                                append = insert[2]
                                insert = insert[1]
                                insert['append'] = append
                                insert = json.dumps(insert)
                                f.write("%s\n" % insert)
                                self.es_file_storage_count += 1
                            f.close()

                        inserts = []
                    break
                insert = json.loads(insert)
                insert['session'] = self.session

                if not insert['doc_type'] in es_ids:
                    continue

                if self.es_file_storage_enabled:
                    f = open(normalize_path(self.es_file_storage), 'a')
                    insert_file = json.dumps(insert)
                    f.write("%s\n" % insert_file)
                    f.close()
                    self.es_file_storage_count += 1

                if not self.nodb:
                    if 'append' in insert:
                        append = insert['append']
                        del insert['append']
                    else:
                        append = None
                    inserts.append((es_ids[insert['doc_type']].format(**insert), insert, append))

                    if len(inserts) >= MAX_BULK:
                        error = Elasticsearch.insert_bulk(inserts)
                        if error and not self.es_file_storage_enabled:
                            # Backup in the file
                            f = open(normalize_path(self.es_file_storage), 'a')
                            for insert in inserts:
                                append = insert[2]
                                insert = insert[1]
                                insert['append'] = append
                                insert = json.dumps(insert)
                                f.write("%s\n" % insert)
                                self.es_file_storage_count += 1
                            f.close()

                        inserts = []
            except queue.Empty:
                if len(inserts) > 0:
                    error = Elasticsearch.insert_bulk(inserts)
                    if error and not self.es_file_storage_enabled:
                        # Backup in the file
                        f = open(normalize_path(self.es_file_storage), 'a')
                        for insert in inserts:
                            append = insert[2]
                            insert = insert[1]
                            insert['append'] = append
                            insert = json.dumps(insert)
                            f.write("%s\n" % insert)
                            self.es_file_storage_count += 1
                        f.close()

                    inserts = []
            except BrokenPipeError:
                break
            except Exception as e:
                traceback.print_exc()
                print('%s: %s' % (type(e), e))

    @classmethod
    def insert_ip(self, host_doc):
        host_doc['doc_type'] = 'ip'
        host_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        host_doc = check_entry(host_doc, ['hostname'], ['rtt'])

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
            self.send(doc)

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
        content_doc = check_entry(content_doc, ['url', 'path', 'share', 'service', 'account'], ['size', 'access'])

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
    def insert_application(self, application_doc):
        application_doc['doc_type'] = 'application'
        application_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        application_doc = check_entry(application_doc, ['url', 'name', 'version', 'installdate'], [])

        to_insert = []
        if check_ip(application_doc['hostname']):
            # 'host' is an IP
            application_doc['ip'] = application_doc['hostname']
            del application_doc['hostname']

            to_insert.append(application_doc)
        else:
            # 'host' is an IP
            ip_list = resolve_hostname(application_doc['hostname'])

            for ip in ip_list:
                # insert hostname in DNS database
                self.insert_dns({
                    'source': application_doc['hostname'],
                    'query_type': 'A',
                    'target': ip,
                })

                application_doc_tmp = copy(application_doc)
                application_doc_tmp['ip'] = ip
                del application_doc_tmp['hostname']

                to_insert.append(application_doc_tmp)

        for doc in to_insert:
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
    def insert_domain_domain(self, domain_doc):
        domain_doc['doc_type'] = 'domain'
        domain_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        domain_doc = check_entry(domain_doc, ['domain', 'parameters', 'sid', 'dn'], [])

        domain_doc['domain'] = domain_doc['domain'].lower()

        if len(domain_doc['domain']) == 0 or domain_doc['domain'] == 'workgroup':
            return

        if 'created_date' in domain_doc:
            domain_doc['created_date'] = int(domain_doc['created_date'].timestamp()*1000)

        self.send(domain_doc)

    @classmethod
    def insert_domain_container(self, container_doc):
        container_doc['doc_type'] = 'domain_container'
        container_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        container_doc = check_entry(container_doc, ['domain', 'guid', 'dn'], [])

        container_doc['domain'] = container_doc['domain'].lower()

        if len(container_doc['domain']) == 0 or container_doc['domain'] == 'workgroup':
            return

        if 'created_date' in container_doc:
            container_doc['created_date'] = int(container_doc['created_date'].timestamp()*1000)

        self.send(container_doc)

    @classmethod
    def insert_domain_ou(self, ou_doc):
        ou_doc['doc_type'] = 'domain_ou'
        ou_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        ou_doc = check_entry(ou_doc, ['domain', 'guid', 'dn'], [])

        ou_doc['domain'] = ou_doc['domain'].lower()

        if len(ou_doc['domain']) == 0 or ou_doc['domain'] == 'workgroup':
            return

        if 'created_date' in ou_doc:
            ou_doc['created_date'] = int(ou_doc['created_date'].timestamp()*1000)

        self.send(ou_doc)

    @classmethod
    def insert_domain_gpo(self, gpo_doc):
        gpo_doc['doc_type'] = 'domain_gpo'
        gpo_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        gpo_doc = check_entry(gpo_doc, ['domain', 'guid', 'dn'], [])

        gpo_doc['domain'] = gpo_doc['domain'].lower()

        if len(gpo_doc['domain']) == 0 or gpo_doc['domain'] == 'workgroup':
            return

        if 'created_date' in gpo_doc:
            gpo_doc['created_date'] = int(gpo_doc['created_date'].timestamp()*1000)

        self.send(gpo_doc)



    @classmethod
    def insert_domain_host(self, host_doc):
        host_doc['doc_type'] = 'domain_host'
        host_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        host_doc = check_entry(host_doc, ['domain', 'hostname', 'os'], ['hostname_ip'])

        host_doc['domain'] = host_doc['domain'].lower()

        if len(host_doc['domain']) == 0 or host_doc['domain'] == 'workgroup':
            return

        if 'created_date' in host_doc:
            host_doc['created_date'] = int(host_doc['created_date'].timestamp()*1000)
        if 'last_logon' in host_doc and host_doc['last_logon'] != None:
            host_doc['last_logon'] = int(host_doc['last_logon'].timestamp()*1000)
        if 'last_password_change' in host_doc:
            host_doc['last_password_change'] = int(host_doc['last_password_change'].timestamp()*1000) if host_doc['last_password_change'] != None else None

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
                # too slow...
                """
                ip_list = resolve_hostname(hostname)
                if len(ip_list) != 0:
                    host_doc['ip'] = [ip_list]
                """

        if 'admin_of' in host_doc:
            if check_ip(host_doc['admin_of']):
                # 'host' is an IP
                append = {'admin_of': [host_doc['admin_of']]}
                host_doc['append'] = append
                del host_doc['admin_of']
            else:
                # 'host' is a hostname
                ip_list = resolve_hostname(host_doc['admin_of'])
                append = {'admin_of': ip_list}
                del host_doc['admin_of']
                host_doc['append'] = append

        if 'tags' in host_doc:
            if not 'append' in host_doc:
                append = {'tags': host_doc['tags']}
                host_doc['append'] = append
            else:
                host_doc['append']['tags'] = host_doc['tags']
            del host_doc['tags']

        self.send(host_doc)

    @classmethod
    def insert_domain_user(self, user_doc):
        user_doc['doc_type'] = 'domain_user'
        user_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        user_doc = check_entry(user_doc, ['domain', 'username'], [])

        user_doc['domain'] = user_doc['domain'].lower()
        user_doc['username'] = user_doc['username'].lower()

        if len(user_doc['domain']) == 0 or user_doc['domain'] == 'workgroup':
            return

        if 'created_date' in user_doc:
            user_doc['created_date'] = int(user_doc['created_date'].timestamp()*1000)
        if 'last_logon' in user_doc and user_doc['last_logon'] != None:
            user_doc['last_logon'] = int(user_doc['last_logon'].timestamp()*1000)
        if 'last_password_change' in user_doc:
            user_doc['last_password_change'] = int(user_doc['last_password_change'].timestamp()*1000) if user_doc['last_password_change'] != None else None

        # deprecated...
        if 'password' in user_doc:
            if not 'append' in user_doc:
                append = {'password': [user_doc['password']] }
                user_doc['append'] = append
            else:
                user_doc['append']['password'] = [user_doc['password']]
            del user_doc['password']

        # deprecated...
        if 'hash' in user_doc:
            if not 'append' in user_doc:
                append = {'hash': [user_doc['hash']] }
                user_doc['append'] = append
            else:
                user_doc['append']['hash'] = [user_doc['hash']]
            del user_doc['hash']

        if 'group' in user_doc:
            if not 'append' in user_doc:
                append = {'group': user_doc['group']}
                user_doc['append'] = append
            else:
                user_doc['append']['group'] = [user_doc['group']]
            del user_doc['group']

        if 'tags' in user_doc:
            if not 'append' in user_doc:
                append = {'tags': user_doc['tags']}
                user_doc['append'] = append
            else:
                user_doc['append']['tags'] = user_doc['tags']
            del user_doc['tags']

        self.send(user_doc)

    @classmethod
    def insert_domain_credential(self, credential_doc):
        if 'password' in credential_doc:
            credential_doc['doc_type'] = 'domain_password'
        elif 'hash' in credential_doc:
            credential_doc['doc_type'] = 'domain_hash'
        else:
            return
        credential_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        credential_doc = check_entry(credential_doc, ['domain', 'username'], ['password', 'format', 'hash'])

        credential_doc['domain'] = credential_doc['domain'].lower()
        credential_doc['username'] = credential_doc['username'].lower()

        self.send(credential_doc)

    @classmethod
    def insert_domain_group(self, group_doc):
        group_doc['doc_type'] = 'domain_group'
        group_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        group_doc = check_entry(group_doc, ['domain', 'groupname'], [])

        group_doc['domain'] = group_doc['domain'].lower()
        group_doc['groupname'] = group_doc['groupname'].lower()

        if len(group_doc['domain']) == 0 or group_doc['domain'] == 'workgroup':
            return

        if 'user' in group_doc:
            if not 'append' in group_doc:
                append = {'user': group_doc['user']}
                group_doc['append'] = append
            else:
                group_doc['append']['user'] = [group_doc['user']]
            del group_doc['user']

        self.send(group_doc)

    @classmethod
    def insert_domain_spn(self, spn_doc):
        spn_doc['doc_type'] = 'domain_spn'
        spn_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        spn_doc = check_entry(spn_doc, ['domain', 'spn', 'username'], [])

        spn_doc['domain'] = spn_doc['domain'].lower()
        spn_doc['username'] = spn_doc['username'].lower()

        if len(spn_doc['domain']) == 0 or spn_doc['domain'] == 'workgroup':
            return

        self.send(spn_doc)

    @classmethod
    def insert_domain_vulnerability(self, vuln_doc):
        vuln_doc['doc_type'] = 'domain_vuln'
        vuln_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        vuln_doc = check_entry(vuln_doc, ['domain', 'name', 'description'], [])

        vuln_doc['domain'] = vuln_doc['domain'].lower()

        if len(vuln_doc['domain']) == 0 or vuln_doc['domain'] == 'workgroup':
            return

        self.send(vuln_doc)

    @classmethod
    def insert_host_linux(self, host_doc):
        host_doc['doc_type'] = 'host_linux'
        host_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        host_doc = check_entry(host_doc, ['hostname', 'host'], [])

        to_insert = []
        if check_ip(host_doc['hostname']):
            # 'hostname' is an IP
            host_doc['ip'] = host_doc['hostname']
            del host_doc['hostname']

            to_insert.append(host_doc)
        else:
            # 'hostname' is an IP
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
    def insert_host_linux_pkg(self, host_doc):
        host_doc['doc_type'] = 'host_linux_pkg'
        host_doc['@timestamp'] = int(datetime.now().timestamp()*1000)
        host_doc = check_entry(host_doc, ['hostname', 'host'], [])

        to_insert = []
        if check_ip(host_doc['hostname']):
            # 'hostname' is an IP
            host_doc['ip'] = host_doc['hostname']
            del host_doc['hostname']

            to_insert.append(host_doc)
        else:
            # 'hostname' is an IP
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

            if Config.config.get('Elasticsearch', 'ssl').lower() == 'true':
                url = 'https://%s:%d' % (es_ip, es_port)
                ssl = True
            else:
                url = 'http://%s:%d' % (es_ip, es_port)
                ssl = False

            username = Config.config.get('Elasticsearch', 'username')
            password = Config.config.get('Elasticsearch', 'password')
            if len(username) != 0:
                self.elasticsearch_instance = (elasticsearch.Elasticsearch([url], max_retries=5, retry_on_timeout=True, http_auth=(username, password), verify_certs=False, ssl_show_warn=False), es_index)
            else:
                self.elasticsearch_instance = (elasticsearch.Elasticsearch([url], max_retries=5, retry_on_timeout=True, verify_certs=False, ssl_show_warn=False), es_index)

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
            Output.minor('Elasticsearch index doesn\'t exist, creating it')

            es[0].indices.create(
                index=es[1],
                body=es_mapping,
                ignore=400 # ignore 400 already exists code
            )

    @classmethod
    def count(self, doc):
        try:
            es = self.get_es_instance()

            res = es[0].count(index=es[1], body=doc)

            return res['count']
        except elasticsearch.exceptions.ConnectionError:
            Output.error("Elasticsearch: Unable to connect to elasticsearch instance")

    @classmethod
    def search(self, doc):
        try:
            es = self.get_es_instance()

            res = helpers.scan(es[0], index=es[1], query=doc)

            return res
        except elasticsearch.exceptions.ConnectionError:
            Output.error("Elasticsearch: Unable to connect to elasticsearch instance")

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
            Output.error("Elasticsearch: Unable to connect to elasticsearch instance")

    @classmethod
    def insert_bulk(self, inserts):
        error = False

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
            Output.error("Elasticsearch: Unable to connect to elasticsearch instance")
            error = True
        except Exception as e:
            Output.error('%s: %s\n%s' % (type(e), e, traceback.format_exc()))
            error = True

        return error

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
            Output.error("Elasticsearch: Unable to connect to elasticsearch instance")

def resolve_hostname(hostname, timeout=5):

    ip_results = []

    try:
        ip_results = resolver.query(hostname, "A")
    except resolver.NXDOMAIN:
        pass
    except resolver.NoAnswer:
        pass
    except resolver.NoNameservers:
        pass
    except dns.exception.Timeout:
        pass

    for ip in ip_results:
        ip = str(ip)

    return [str(ip) for ip in ip_results]

