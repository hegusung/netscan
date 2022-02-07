import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from utils.parsers import *
from lib.httpscan.http import HTTP

creds = [
    'nagios:nagios',
    'admin:admin',
    'root:Passw0rd',
    'root:mysql',
    'root:root',
    'root:chippc',
    'root:',
    'root:nagiosxi',
    'root:usbw',
    'cloudera:cloudera',
    'root:cloudera',
    'root:moves',
    'moves:moves',
    'root:testpw',
    'root:mysql',
    'root:p@ck3tf3nc3',
    'mcUser:medocheck123',
    'root:mktt',
]

pma_urls = [
    '',
    'pma',
    'phpmyadmin',
    'phpMyAdmin',
]

class Module:
    name = 'PHPMyAdmin'
    description = 'Discover and bruteforce phpmyadmin'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        for url in pma_urls:
            if url != '':
                url = os.path.join(target['path'], url)
            else:
                url = target['path']

            if not '.' in url.split('/')[0]:
                if not url.endswith('/'):
                    url = url + '/'

            res = http.get(url)

            if res and res['code'] in [200] and 'phpmyadmin' in res['title'].lower():
                http_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'protocol': 'tcp',
                    'service': 'http',
                    'url': http.url(url),
                    'http': {
                        'path': url,
                        'code': res['code'],
                        'server': res['server'],
                        'title': res['title'],
                        'content-type': res['content-type'],
                    },
                    'tags': ['phpmyadmin']
                }
                DB.insert_http_url(http_info)

                Output.highlight({'target': http.url(url), 'message': 'PhpMyAdmin interface'})

                form = None
                for f in res['forms']:
                    if not 'name' in f:
                        continue

                    if 'login' in f['name'].lower():
                        form = f
                        break

                if "phpmyadmin - error" in res['html'].lower():
                    continue

                if not form:
                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(url),
                        'name': 'PhpMyAdmin interface without authentication',
                        'description': 'PhpMyAdmin interface %s is accessible without authentication' % http.url(url),
                    }
                    DB.insert_vulnerability(vuln_info)

                    Output.vuln({'target': http.url(url), 'message': 'PhpMyAdmin accessible without authentication'})
                else:
                    if args['bruteforce']:
                        Output.highlight({'target': http.url(url), 'message': 'Starting bruteforce...'})
                        for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                            username, password = cred.split(':')

                            data = http.get(url)

                            if not data:
                                continue

                            form = None
                            for f in data['forms']:
                                if not 'name' in f:
                                    continue

                                if 'login' in f['name'].lower():
                                    form = f
                                    break

                            if not form:
                                continue

                            for arg in form['args']:
                                if 'username' in arg.lower():
                                    form['args'][arg] = username

                                if 'password' in arg.lower():
                                    form['args'][arg] = password

                            res = http.send_form(url, form, html=data['html'], cookies=data['cookies'])

                            after_auth_form = None
                            for f in res['forms']:
                                if not 'name' in f:
                                    continue

                                if 'login' in f['name'].lower():
                                    after_auth_form = f
                                    break

                            if after_auth_form != None:
                                continue

                            Output.success({'target': http.url(url), 'message': 'Authentication success to PhpMyAdmin with login %s and password %s' % (username, password)})

                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'http',
                                'url': http.url(url),
                                'type': 'password',
                                'username': username,
                                'password': password,
                                'tags': ['phpmyadmin'],
                            }
                            DB.insert_credential(cred_info)

                            vuln_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'http',
                                'url': http.url(url),
                                'name': 'Default or predictable credentials on PhpMyAdmin service',
                                'description': 'PhpMyAdmin %s possess the following default or weak credentials: %s:%s' % (http.url(url), username, password),
                            }
                            DB.insert_vulnerability(vuln_info)



