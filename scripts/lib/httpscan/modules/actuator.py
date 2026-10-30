import os.path
import json
from urllib.parse import urljoin

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

class Module:
    name = 'Actuator'
    description = 'Search for Spring Boot actuators'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        for uri in ["dump", "trace", "logfile", "shutdown", "mappings", "env", "actuator", "heapdump", "gateway/routes", "metrics", "threaddump", "scheduledtasks"]:
            # Without /actuator
            response = http.get(os.path.join(target['path'], uri))

            if response != None and response['code'] == 200 and ('json' in response['content-type'] or response['content-type'] == 'application/octet-stream'):
                #data = json.loads(response['html'])

                Output.highlight({'target': http.url(os.path.join(target['path'], uri)), 'message': '[%s] Actuator endpoint' % self.name})

                vuln_info = {
                    'host': target['hostname'],
                    'port': target['port'],
                    'service': 'http',
                    'url': http.url(os.path.join(target['path'], uri)),
                    'name': 'Actuator endpoint available',
                    'description': 'Actuator endpoint is accessible at %s' % http.url(os.path.join(target['path'], uri)),
                }
                DB.insert_vulnerability(vuln_info)

            # With /actuator
            response = http.get(os.path.join(target['path'], 'actuator', uri))

            if response != None and response['code'] == 200 and ('json' in response['content-type'] or response['content-type'] == 'application/octet-stream'):
                #data = json.loads(response['html'])

                Output.highlight({'target': http.url(os.path.join(target['path'], 'actuator', uri)), 'message': '[%s] Actuator endpoint' % self.name})

                vuln_info = {
                    'host': target['hostname'],
                    'port': target['port'],
                    'service': 'http',
                    'url': http.url(os.path.join(target['path'], uri)),
                    'name': 'Actuator endpoint available',
                    'description': 'Actuator endpoint is accessible at %s' % http.url(os.path.join(target['path'], uri)),
                }
                DB.insert_vulnerability(vuln_info)


