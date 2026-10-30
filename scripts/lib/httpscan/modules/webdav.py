import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

class Module:
    name = 'WebDAV'
    description = 'Attempt a PROPFIND request to check a webDav server (webdav)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        response = http.propfind(target['path'])
        if response and response['code'] in [200,207]:
            Output.vuln({'target': http.url(target['path']), 'message': '[%s] WebDAV server' % self.name})

            vuln_info = {
                'host': target['hostname'],
                'port': target['port'],
                'service': 'http',
                'url': http.url(target['path']),
                'name': 'WebDAV (PROPFIND request success)',
                'description': 'Files can be accessed via a PROPFIND request at %s' % http.url(target['path']),
            }
            DB.insert_vulnerability(vuln_info)





