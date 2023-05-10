import os.path
import json
from urllib.parse import urljoin

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

class Module:
    name = 'CouchDB'
    description = 'Search for couchdb databases (no authentication)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        response = http.get('/')

        if response != None and response['code'] == 200 and response['content-type'] == 'application/json':
            data = json.loads(response['html'])

            if 'couchdb' in data:
                Output.highlight({'target': http.url('/'), 'message': '[%s] CouchDB database version %s' % (self.name, data["version"])})

                databases = []
                response = http.get('/_all_dbs')
                if response['code'] == 200 and response['content-type'] == 'application/json':
                    databases = json.loads(response['html'])

                    Output.vuln({'target': http.url("/_all_dbs"), 'message': '[%s] CouchDB accessible without authentication' % self.name})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url("/_all_dbs"),
                        'name': 'CouchDB anonymous access',
                        'description': 'CouchDB database %s accessible without authentication' % http.url("/_all_dbs"),
                    }
                    DB.insert_vulnerability(vuln_info)


                    text = "[%s] Database\n" % self.name
                    for db in databases:
                        uri = "/%s/_all_docs" % db
                        resp = http.get(uri)
                        code = resp['code']
                        text += "\t\t\t\t[%d] Database : %s => %s\n" % (code, db.ljust(20), http.url(uri) + "?limit=10")

                    Output.highlight({'target': http.url('/'), 'message': text})


