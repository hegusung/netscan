import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

class Module:
    name = 'PUT'
    description = 'Attempt a PUT request to check file upload (webdav)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        random_str = gen_random_string()
        payload = 'PUT check: %s' % random_str

        response = http.put(os.path.join(target['path'], '%s.txt' % random_str), payload)
        if response and response['code'] in [200,201]:
            response = http.get(os.path.join(target['path'], '%s.txt' % random_str))

            if response and payload in response['html']:
                Output.vuln({'target': http.url(target['path']), 'message': '[%s] Vulnerable to PUT file upload' % self.name})

                vuln_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'http',
                    'url': http.url(target['path']),
                    'name': 'PUT upload file',
                    'description': 'Files can be uploaded via a PUT request at %s' % http.url(target['path']),
                }
                DB.insert_vulnerability(vuln_info)





