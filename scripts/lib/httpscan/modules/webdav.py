import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP


def is_webdav_response(response):
    if not response:
        return False
    if response['code'] == 207:
        return True

    headers = response.get('headers', {})
    if any(key.lower() == 'dav' for key in headers):
        return True

    content_type = (response.get('content-type') or '').lower()
    body = (response.get('html') or '').lower()
    return (
        response['code'] == 200
        and content_type in ('application/xml', 'text/xml')
        and '<' in body
        and 'multistatus' in body
    )


class Module:
    name = 'WebDAV'
    description = 'Attempt a PROPFIND request to check a webDav server (webdav)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        response = http.propfind(target['path'])
        if is_webdav_response(response):
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





