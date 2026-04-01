import elasticsearch
import hashlib
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
    'tool': 'ip_{session}_{@timestamp}',
    'ip': 'ip_{session}_{host}',
    'dns': 'dns_{session}_{source}_{query_type}_{target}',
    'port': 'port_{session}_{host}_{protocol}_{port}',
    'script': 'script_{session}_{host}_{protocol}_{port}_{name}',
    'http': 'http_{session}_{url}',
    'content': 'content_{session}_{url}_{account}_{share}_{path}',
    'application': 'application_{session}_{url}_{name}_{version}',
    'database': 'database_{session}_{url}_{account}_{database}_{table}',
    'cred_password': 'cred_password_{session}_{url}_{username}_{password}',
    'cred_hash': 'cred_hash_{session}_{url}_{username}_{format}_{hash}',
    'vuln': 'vuln_{session}_{url}_{name}_{description}',
    'secret': 'secret_{session}_{filepath}_{line}',
    'snmp': 'snmp_{session}_{host}_{port}_{snmp_key}',
    # AD
    'domain': 'domain_domain_{session}_{domain}',
    'domain_container': 'domain_container_{session}_{domain}_{guid}',
    'domain_ou': 'domain_ou_{session}_{domain}_{guid}',
    'domain_gpo': 'domain_gpo_{session}_{domain}_{guid}',
    'domain_gpochange': 'domain_gpochange_{session}_{domain}_{guid}_{action}',
    'domain_host': 'domain_host_{session}_{domain}_{hostname}',
    'domain_user': 'domain_user_{session}_{domain}_{username}',
    'domain_group': 'domain_group_{session}_{domain}_{groupname}',
    #'domain_spn': 'domain_spn_{session}_{domain}_{spn}',
    'domain_password': 'domain_password_{session}_{domain}_{username}_{password}',
    'domain_hash': 'domain_hash_{session}_{domain}_{username}_{format}_{hash}',
    'domain_dns': 'domain_dns_{session}_{dns}',
    # ADCS
    'domain_ntauthcertificate': 'domain_ntauthcertificate_{session}_{domain}_{name}',
    'domain_rootca': 'domain_rootca_{session}_{domain}_{name}',
    'domain_aiaca': 'domain_aiaca_{session}_{domain}_{name}',
    'domain_enrollmentservice': 'domain_enrollmentservice_{session}_{domain}_{name}',
    'domain_certificatetemplate': 'domain_certificatetemplate_{session}_{domain}_{name}',
    # Linux
    'host_linux': 'host_linux_{session}_{host}',
    'host_linux_pkg': 'host_linux_pkg_{session}_{host}_{pkg_name}',
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
            "id": {
                "type": "text",
                "fields": {
                    "keyword":{
                        "type": "keyword",
                        "ignore_above": 15000
                    }
                }
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
            "last_access": {
                "type": "date"
            },
            "last_modification": {
                "type": "date"
            },
            "last_logon": {
                "type": "date"
            },
            "last_logon_timestamp": {
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

            # Add generic data : timestamp
            doc['@timestamp'] = int(datetime.now().timestamp()*1000)

            # tag system
            if 'tags' in doc:
                if not 'append' in doc:
                    append = {'tags': doc['tags']}
                    doc['append'] = append
                else:
                    doc['append']['tags'] = doc['tags']
                del doc['tags']

            # if host=hostname, try to resolve, save ip as host
            if 'host' in doc:
                to_send = []
                if check_ip(doc['host']): # host = IP 
                    # 'host' is an IP
                    doc['ip'] = doc['host']

                    to_send.append(doc)
                else:
                    # 'host' is an Hostname, try to resolve
                    ip_list = resolve_hostname(doc['host'])

                    if len(ip_list) != 0:
                        for ip in ip_list:
                            # insert hostname in DNS database
                            self.insert_dns({
                                'source': doc['host'],
                                'query_type': 'A',
                                'target': ip,
                            })

                            doc_tmp = copy(doc)
                            doc_tmp['ip'] = ip
                            if not 'hostname' in doc_tmp:
                                doc_tmp['hostname'] = doc['host']
                            doc_tmp['host'] = ip

                            to_send.append(doc_tmp)
                    else:
                        # Fallback to host = hostname
                        if not 'hostname' in doc:
                            doc['hostname'] = doc['host']
                        to_send.append(doc)

                for to_send_doc in to_send:
                    # Create the host_port key
                    if 'host' in to_send_doc and 'port' in to_send_doc:
                        to_send_doc['host_port'] = "%s:%d" % (to_send_doc['host'], to_send_doc['port'])

                    data = json.dumps(to_send_doc)
                    self.db_queue.put(data, True, 60)

            else:
                data = json.dumps(doc)
                self.db_queue.put(data, True, 60)
        else:
            self.db_queue.put(None, True, 60)

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
                    document_id = es_ids[insert['doc_type']].format(**insert)
                    document_id_hash = hashlib.sha256(document_id.encode()).hexdigest()
                    inserts.append((document_id_hash, insert, append))

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
            except EOFError:
                break
            except Exception as e:
                traceback.print_exc()
                print('%s: %s' % (type(e), e))

    @classmethod
    def save_start(self):
        
        netscan = "netscan"
        tool = os.path.basename(sys.argv[0]).split(".")[0]
        args = " ".join(sys.argv[1:])

        cmdline = "%s %s %s" % (netscan, tool, args)

        tool_doc = {}
        tool_doc['doc_type'] = 'tool'
        tool_doc['cmdline'] = cmdline
        tool_doc['tool'] = tool

        self.send(tool_doc)


    @classmethod
    def insert_ip(self, host_doc):
        host_doc['doc_type'] = 'ip'
        host_doc = check_entry(host_doc, ['host'], ['rtt'])

        self.send(host_doc)

    @classmethod
    def insert_dns(self, dns_doc):
        dns_doc['doc_type'] = 'dns'
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
        host_doc = check_entry(host_doc, ['host', 'port'], ['protocol', 'service', 'subservice', 'version', 'nmap_service', 'nmap_version', 'banner', 'tags'])

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

        self.send(host_doc)

    @classmethod
    def insert_script(self, script_doc):
        script_doc['doc_type'] = 'script'
        script_doc = check_entry(script_doc, ['host', 'port', 'nmap_service', 'name', 'output'], [])

        # add protocol
        script_doc['protocol'] = script_doc['protocol'].lower() if 'protocol' in script_doc else 'tcp'
        # make sure port is an int
        if 'port' in script_doc:
            script_doc['port'] = int(script_doc['port'])

        self.send(script_doc)

    @classmethod
    def insert_http_url(self, http_doc):
        http_doc['doc_type'] = 'http'
        http_doc = check_entry(http_doc, ['host', 'port', 'service', 'url', 'http'], [])

        # add protocol
        http_doc['protocol'] = http_doc['protocol'].lower() if 'protocol' in http_doc else 'tcp'
        # make sure port is an int
        if 'port' in http_doc:
            http_doc['port'] = int(http_doc['port'])

        self.send(http_doc)

    @classmethod
    def insert_content(self, content_doc):
        content_doc['doc_type'] = 'content'
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

        self.send(content_doc)

    @classmethod
    def insert_application(self, application_doc):
        application_doc['doc_type'] = 'application'
        application_doc = check_entry(application_doc, ['url', 'name', 'version', 'installdate'], [])

        self.send(application_doc)

    @classmethod
    def insert_database(self, database_doc):
        database_doc['doc_type'] = 'database'
        database_doc = check_entry(database_doc, ['url', 'service', 'database', 'table'], ['account'])

        database_doc['service'] = database_doc['service'].lower()

        if not 'account' in database_doc:
            database_doc['account'] = 'unknown'

        self.send(database_doc)

    @classmethod
    def insert_credential(self, credential_doc):
        if 'password' in credential_doc:
            credential_doc['doc_type'] = 'cred_password'
        elif 'hash' in credential_doc:
            credential_doc['doc_type'] = 'cred_hash'
        else:
            return
        credential_doc = check_entry(credential_doc, ['url', 'service', 'username'], ['password', 'format', 'hash'])

        credential_doc['service'] = credential_doc['service'].lower()

        if 'hash' in credential_doc:
            if credential_doc['hash'].startswith('aad3b435b51404eeaad3b435b51404ee:'):  # Remove empty LN
                credential_doc['hash'] = credential_doc['hash'][len('aad3b435b51404eeaad3b435b51404ee:'):]

        self.send(credential_doc)

    @classmethod
    def insert_vulnerability(self, vulnerability_doc):
        vulnerability_doc['doc_type'] = 'vuln'
        vulnerability_doc = check_entry(vulnerability_doc, ['url', 'service', 'name', 'description'], [])

        vulnerability_doc['service'] = vulnerability_doc['service'].lower()

        self.send(vulnerability_doc)

    @classmethod
    def insert_secret(self, secret_doc):
        secret_doc['doc_type'] = 'secret'
        secret_doc = check_entry(secret_doc, ['filepath', 'secret_name', 'line', 'reliability'], [])

        if not secret_doc['filepath'].startswith("LSA:"):
            secret_doc['name'] = os.path.basename(secret_doc['filepath'])

            if '.' in secret_doc['name']:
                secret_doc['ext'] = secret_doc['name'].split('.')[-1].lower()

        secret_doc['service'] = secret_doc['service']
        self.send(secret_doc)

    @classmethod
    def insert_snmp_entry(self, snmp_doc):
        snmp_doc['doc_type'] = 'snmp'
        snmp_doc = check_entry(snmp_doc, ['host', 'port', 'snmp_key', 'snmp_type', 'snmp_value'], [])

        self.send(snmp_doc)

    @classmethod
    def insert_domain_domain(self, domain_doc):
        domain_doc['doc_type'] = 'domain'
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
        gpo_doc = check_entry(gpo_doc, ['domain', 'guid', 'dn'], [])

        gpo_doc['domain'] = gpo_doc['domain'].lower()

        if len(gpo_doc['domain']) == 0 or gpo_doc['domain'] == 'workgroup':
            return

        if 'created_date' in gpo_doc:
            gpo_doc['created_date'] = int(gpo_doc['created_date'].timestamp()*1000)

        self.send(gpo_doc)

    @classmethod
    def insert_domain_gpochange(self, gpo_doc):
        gpo_doc['doc_type'] = 'domain_gpochange'
        gpo_doc = check_entry(gpo_doc, ['domain', 'guid', 'dn'], [])

        gpo_doc['domain'] = gpo_doc['domain'].lower()

        if len(gpo_doc['domain']) == 0 or gpo_doc['domain'] == 'workgroup':
            return

        self.send(gpo_doc)


    @classmethod
    def insert_domain_dns(self, dns_doc):
        dns_doc['doc_type'] = 'domain_dns'
        dns_doc = check_entry(dns_doc, ['domain', 'dns'], [])

        dns_doc['domain'] = dns_doc['domain'].lower()

        if len(dns_doc['domain']) == 0 or dns_doc['domain'] == 'workgroup':
            return

        self.send(dns_doc)


    @classmethod
    def insert_domain_host(self, host_doc):
        host_doc['doc_type'] = 'domain_host'
        host_doc = check_entry(host_doc, ['domain', 'hostname', 'os'], ['hostname_ip'])

        host_doc['domain'] = host_doc['domain'].lower()

        if len(host_doc['domain']) == 0 or host_doc['domain'] == 'workgroup':
            return

        if 'created_date' in host_doc:
            host_doc['created_date'] = int(host_doc['created_date'].timestamp()*1000)
        if 'last_logon' in host_doc and host_doc['last_logon'] != None:
            host_doc['last_logon'] = int(host_doc['last_logon'].timestamp()*1000)
        if 'last_logon_timestamp' in host_doc and host_doc['last_logon_timestamp'] != None:
            host_doc['last_logon_timestamp'] = int(host_doc['last_logon_timestamp'].timestamp()*1000)
        if 'last_password_change' in host_doc:
            host_doc['last_password_change'] = int(host_doc['last_password_change'].timestamp()*1000) if host_doc['last_password_change'] != None else None

        if len(host_doc['hostname']) == 0:
            host_doc['hostname'] = "*no hostname*"
        else:
            host_doc['hostname'] = host_doc['hostname'].lower()

        if 'admin' in host_doc:
            # 'host' is a hostname
            admin_list = host_doc['admin']
            if type(admin_list) != list:
                admin_list = [admin_list]

            append = {'admin': admin_list}
            del host_doc['admin']
            host_doc['append'] = append

        self.send(host_doc)

    @classmethod
    def insert_domain_user(self, user_doc):
        user_doc['doc_type'] = 'domain_user'
        user_doc = check_entry(user_doc, ['domain', 'username'], [])

        user_doc['domain'] = user_doc['domain'].lower()
        user_doc['username'] = user_doc['username'].lower()

        if len(user_doc['domain']) == 0 or user_doc['domain'] == 'workgroup':
            return

        if 'created_date' in user_doc and user_doc['created_date'] != None:
            user_doc['created_date'] = int(user_doc['created_date'].timestamp()*1000)
        if 'last_logon' in user_doc and user_doc['last_logon'] != None:
            user_doc['last_logon'] = int(user_doc['last_logon'].timestamp()*1000)
        if 'last_logon_timestamp' in user_doc and user_doc['last_logon_timestamp'] != None:
            user_doc['last_logon_timestamp'] = int(user_doc['last_logon_timestamp'].timestamp()*1000)
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

        self.send(user_doc)

    @classmethod
    def insert_domain_credential(self, credential_doc):
        if 'password' in credential_doc:
            credential_doc['doc_type'] = 'domain_password'
        elif 'hash' in credential_doc:
            credential_doc['doc_type'] = 'domain_hash'
        else:
            return

        credential_doc = check_entry(credential_doc, ['domain', 'username'], ['password', 'format', 'hash'])

        if 'hash' in credential_doc:
            if credential_doc['hash'].startswith('aad3b435b51404eeaad3b435b51404ee:'):  # Remove empty LN
                credential_doc['hash'] = credential_doc['hash'][len('aad3b435b51404eeaad3b435b51404ee:'):]

        credential_doc['domain'] = credential_doc['domain'].lower()
        credential_doc['username'] = credential_doc['username'].lower()

        self.send(credential_doc)

    @classmethod
    def insert_domain_group(self, group_doc):
        group_doc['doc_type'] = 'domain_group'
        group_doc = check_entry(group_doc, ['domain', 'groupname'], [])

        group_doc['domain'] = group_doc['domain'].lower()
        group_doc['groupname'] = group_doc['groupname'].lower()

        if len(group_doc['domain']) == 0 or group_doc['domain'] == 'workgroup':
            return

        if 'created_date' in group_doc and group_doc['created_date'] != None:
            group_doc['created_date'] = int(group_doc['created_date'].timestamp()*1000)

        if 'user' in group_doc:
            if not 'append' in group_doc:
                append = {'user': group_doc['user']}
                group_doc['append'] = append
            else:
                group_doc['append']['user'] = [group_doc['user']]
            del group_doc['user']

        self.send(group_doc)

    @classmethod
    def insert_domain_ntauthcertificate(self, ca_doc):
        ca_doc['doc_type'] = 'domain_ntauthcertificate'
        ca_doc = check_entry(ca_doc, ['domain', 'name'], [])

        ca_doc['domain'] = ca_doc['domain'].lower()
        ca_doc['name'] = ca_doc['name'].lower()

        if len(ca_doc['domain']) == 0 or ca_doc['domain'] == 'workgroup':
            return

        if 'created_date' in ca_doc and ca_doc['created_date'] != None:
            ca_doc['created_date'] = int(ca_doc['created_date'].timestamp()*1000)

        self.send(ca_doc)

    @classmethod
    def insert_domain_rootca(self, ca_doc):
        ca_doc['doc_type'] = 'domain_rootca'
        ca_doc = check_entry(ca_doc, ['domain', 'name'], [])

        ca_doc['domain'] = ca_doc['domain'].lower()
        ca_doc['name'] = ca_doc['name'].lower()

        if len(ca_doc['domain']) == 0 or ca_doc['domain'] == 'workgroup':
            return

        if 'created_date' in ca_doc and ca_doc['created_date'] != None:
            ca_doc['created_date'] = int(ca_doc['created_date'].timestamp()*1000)

        self.send(ca_doc)

    @classmethod
    def insert_domain_aiaca(self, ca_doc):
        ca_doc['doc_type'] = 'domain_aiaca'
        ca_doc = check_entry(ca_doc, ['domain', 'name'], [])

        ca_doc['domain'] = ca_doc['domain'].lower()
        ca_doc['name'] = ca_doc['name'].lower()

        if len(ca_doc['domain']) == 0 or ca_doc['domain'] == 'workgroup':
            return

        if 'created_date' in ca_doc and ca_doc['created_date'] != None:
            ca_doc['created_date'] = int(ca_doc['created_date'].timestamp()*1000)

        self.send(ca_doc)

    @classmethod
    def insert_domain_enrollment_service(self, es_doc):
        es_doc['doc_type'] = 'domain_enrollmentservice'
        es_doc = check_entry(es_doc, ['domain', 'name'], [])

        es_doc['domain'] = es_doc['domain'].lower()
        es_doc['name'] = es_doc['name'].lower()

        if len(es_doc['domain']) == 0 or es_doc['domain'] == 'workgroup':
            return

        if 'created_date' in es_doc and es_doc['created_date'] != None:
            es_doc['created_date'] = int(es_doc['created_date'].timestamp()*1000)

        self.send(es_doc)

    @classmethod
    def insert_domain_certificate_template(self, ct_doc):
        ct_doc['doc_type'] = 'domain_certificatetemplate'
        ct_doc = check_entry(ct_doc, ['domain', 'name'], [])

        ct_doc['domain'] = ct_doc['domain'].lower()
        ct_doc['name'] = ct_doc['name'].lower()

        if len(ct_doc['domain']) == 0 or ct_doc['domain'] == 'workgroup':
            return

        if 'created_date' in ct_doc and ct_doc['created_date'] != None:
            ct_doc['created_date'] = int(ct_doc['created_date'].timestamp()*1000)

        self.send(ct_doc)


    @classmethod
    def insert_domain_vulnerability(self, vuln_doc):
        vuln_doc = check_entry(vuln_doc, ['host', 'domain', 'name', 'description'], [])

        vuln_doc['port'] = 445
        vuln_doc['url'] = "domain:%s" % vuln_doc['domain'].lower()
        vuln_doc['service'] = 'domain'

        vuln_doc['domain'] = vuln_doc['domain'].lower()

        if len(vuln_doc['domain']) == 0 or vuln_doc['domain'] == 'workgroup':
            return

        self.insert_vulnerability(vuln_doc)

    @classmethod
    def insert_host_linux(self, host_doc):
        host_doc['doc_type'] = 'host_linux'
        host_doc = check_entry(host_doc, ['host', 'host'], [])

        self.send(host_doc)

    @classmethod
    def insert_host_linux_pkg(self, host_doc):
        host_doc['doc_type'] = 'host_linux_pkg'
        host_doc = check_entry(host_doc, ['host', 'host'], [])

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
    def delete_by_query(self, query):
        try:
            es = self.get_es_instance()

            res = es[0].delete_by_query(index=es[1], body=query)

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

resolved = {}
def resolve_hostname(hostname, timeout=30):

    ip_results = []

    if hostname in resolved:
        return resolved[hostname]

    try:
        ip_results = resolver.resolve(hostname, "A", tcp=True)
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

    resolved[hostname] = [str(ip) for ip in ip_results]
    return resolved[hostname]

