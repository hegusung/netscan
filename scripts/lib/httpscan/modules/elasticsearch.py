import os.path
import json
from urllib.parse import urljoin

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

class Module:
    name = 'Elasticsearch'
    description = 'Search for elasticsearch databases (no authentication, CVE-2015-1427) [ports: 9200]'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        response = http.get('/')

        if response['code'] == 200 and response['content-type'] == 'application/json':
            data = json.loads(response['html'])

            if 'X-elastic-product' in response['headers'] and response['headers']['X-elastic-product'] == 'Elasticsearch':
                Output.highlight({'target': http.url('/'), 'message': '[%s] Elasticsearch database version %s' % (self.name, data["version"]['number'])})

                version_tuple = tuple(int(i) for i in data['version']['number'].split('.'))

                if version_tuple < (1, 3, 8) or version_tuple >= (1, 4, 0) and version_tuple < (1, 4, 3):
                    Output.vuln({'target': http.url("/"), 'message': '[%s] Vulnerable to CVE-2015-1427' % self.name})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url("/"),
                        'name': 'Elasticseach RCE (CVE-2015-1427)',
                        'description': 'Elasticsearch database %s is vulnerable to CVE-2015-1427' % http.url("/"),
                    }
                    DB.insert_vulnerability(vuln_info)

                response = http.get('/_cat/indices?format=json')
                if response['code'] == 200 and response['content-type'] == 'application/json':
                    json_data = json.loads(response['html'])

                    Output.vuln({'target': http.url("/_cat/indices"), 'message': '[%s] Accessible without authentication' % self.name})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url("/_cat/indices"),
                        'name': 'Elasticsearch anonymous access',
                        'description': 'Elasticsearch database %s accessible without authentication' % http.url("/_cat/indices"),
                    }
                    DB.insert_vulnerability(vuln_info)

                    text = "[%s] Elasticsearch indices\n" % self.name
                    for db in json_data:
                        uri = "/%s" % db['index']
                        resp = http.get(uri)
                        code = resp['code']
                        text += "\t\t\t\t[%d] Database : %s (%s documents) => %s\n" % (code, db['index'].ljust(40), db['docs.count'], http.url(uri) + "")

                    Output.highlight({'target': http.url('/'), 'message': text})


