import os.path
from copy import copy
from urllib.parse import urljoin

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

# Techniques taken from: https://github.com/lobuhi/byp4xx

class Module:
    name = '403'
    description = 'Attempt to bypass 403 forbidden using various techniques'

    def run(self, target, args, useragent, proxy, timeout):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        res = http.get(target['path'])

        if res['code'] == 403:
            # Path related tricks
            # %2e
            path = os.path.join('/%2e', target['path'])
            check_bypass(target, http, path)
            # /.
            path = os.path.join(target['path'], '.')
            check_bypass(target, http, path)
            # ?
            path = target['path'] + '?'
            check_bypass(target, http, path)
            # ??
            path = target['path'] + '??'
            check_bypass(target, http, path)
            # //
            path = '/' + target['path'] + '//'
            check_bypass(target, http, path)
            # /./
            path = '/.' + target['path'] + '/./'
            check_bypass(target, http, path)
            # /
            path = target['path'] + '/'
            check_bypass(target, http, path)
            # /.randomstring
            path = target['path'] + '/.randomstring'
            check_bypass(target, http, path)
            # ..;/
            path = target['path'] + '..;/'
            check_bypass(target, http, path)

            # Headers related tricks
            # Referer
            check_bypass(target, http, target['path'], header={'Referer': http.url(target['path'])})
            # X-Custom-IP-Authorization: 127.0.0.1
            check_bypass(target, http, target['path'], header={'X-Custom-IP-Authorization': '127.0.0.1'})
            # X-Custom-IP-Authorization and ..;/ 
            check_bypass(target, http, target['path'] + '..;/', header={'X-Custom-IP-Authorization': '127.0.0.1'})
            # X-Original-URL
            check_bypass(target, http, target['path'], header={'X-Original-URL': target['path']})
            # X-Rewrite-URL
            check_bypass(target, http, target['path'], header={'X-Rewrite-URL': target['path']})
            # X-Originating-IP
            check_bypass(target, http, target['path'], header={'X-Originating-IP': '127.0.0.1'})
            # X-Forwarded-For
            check_bypass(target, http, target['path'], header={'X-Forwarded-For': '127.0.0.1'})
            # X-Remote-IP
            check_bypass(target, http, target['path'], header={'X-Remote-IP': '127.0.0.1'})
            # X-Client-IP
            check_bypass(target, http, target['path'], header={'X-Client-IP': '127.0.0.1'})
            # X-Host
            check_bypass(target, http, target['path'], header={'X-Host': '127.0.0.1'})
            # X-Forwared-Host
            check_bypass(target, http, target['path'], header={'X-Forwared-Host': '127.0.0.1'})

def check_bypass(target, http, path, header={}):
    res = http.get(path)

    if not res:
        return

    if res['code'] in [200, 302]:
        # bypass success !
        head_message = '403 bypass success using '
        bypasses = []
        if target['path'] != path:
            bypasses.append('bypass path: %s' % http.url(path))
        if header != {}:
            bypasses.append('header: %s=%s' % (headers.keys()[0], headers.values()[0]))
        message = head_message + ' and '.join(bypasses)

        Output.vuln({'target': http.url(target['path']), 'message': message})

        vuln_info = {
            'hostname': target['hostname'],
            'port': target['port'],
            'service': 'http',
            'url': http.url(target['path']),
            'name': '403 bypass',
            'description': message,
        }
        DB.insert_vulnerability(vuln_info)
