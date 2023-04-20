import os.path
from urllib.parse import urljoin

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

# Source: https://medium.com/@madrobot/exploiting-jboss-like-a-boss-223a8b108206
# Source: 

creds = [
    "admin:admin",
    "admin:jboss",
    "admin:root",
    "admin:JBoss",
    "admin:wildfly",
    "admin:Wildfly",
    "root:root",
    "root:admin",
    "root:jboss",
    "root:JBoss",
    "root:wildfly",
    "root:Wildfly",
    "jboss:jboss",
    "jboss:JBoss",
    "jboss:admin",
    "jboss:root",
    "wildfly:wildfly",
    "wildfly:Wildfly",
    "wildfly:admin",
    "wildfly:root",
]

jboss_urls = [
    "jmx-console",
    "web-console/ServerInfo.jsp",
    "invoker/readonly",
    "invoker/JMXInvokerServlet",
]

auth_5_6_urls = [
    "admin-console/login.seam",
]
auth_7_8_urls = [
    "console/App.html",
]


class Module:
    name = 'JBoss'
    description = 'Discover and exploit JBoss (weak/default password, no authentication)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        for url in jboss_urls + auth_5_6_urls + auth_7_8_urls:
            full_url = os.path.join(target['path'], url)

            res = http.get(full_url)

            if not res or not res['code'] in [200,401,500]:
                continue

            if 'jboss' in res['title'].lower():
                http_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'protocol': 'tcp',
                    'service': 'http',
                    'url': http.url(full_url),
                    'http': {
                        'path': full_url,
                        'code': res['code'],
                        'server': res['server'],
                        'title': res['title'],
                        'content-type': res['content-type'],
                    },
                    'tags': ['jboss']
                }
                DB.insert_http_url(http_info)

                res['message_type'] = 'http'
                res['target'] = http.url(full_url)
                Output.write(res)


            if url in jboss_urls:
                # JBoss should be a safe service
                if safe and res['code'] in [200] and ('apache-coyote' in res['server'].lower() or 'jboss' in res['title'].lower()):
                    Output.vuln({'target': http.url(full_url), 'message': 'JBoss url accessible without authentication'})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(full_url),
                        'name': 'JBoss url accessible without authentication',
                        'description': 'Jboss interface %s is accessible without authentication' % http.url(full_url),
                    }
                    DB.insert_vulnerability(vuln_info)
                elif res['code'] in [500] and url == 'invoker/readonly' and 'jboss' in res['title'].lower():
                    Output.vuln({'target': http.url(full_url), 'message': 'JBoss vulnerable to CVE-2017-12149'})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(full_url),
                        'name': 'JBoss vulnerable to CVE-2017-12149',
                        'description': 'Jboss interface %s is vulnerable to CVE-2019-12149' % http.url(full_url),
                    }
                    DB.insert_vulnerability(vuln_info)
                elif res['code'] in [401] and ('apache-coyote' in res['server'].lower() or 'jboss' in res['title'].lower()):
                    try:
                        auth_type = res['auth_type']

                        if args['bruteforce']:
                            Output.highlight({'target': http.url(full_url), 'message': 'Starting bruteforce...'})
                            for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                                username, password = cred.split(':')

                                res = http.get(full_url, auth=(auth_type, username, password))

                                if res['code'] in [200]:
                                    Output.success({'target': http.url(full_url), 'message': 'Authentication success with login %s and password %s' % (username, password)})

                                    cred_info = {
                                        'hostname': target['hostname'],
                                        'port': target['port'],
                                        'service': 'http',
                                        'url': http.url(full_url),
                                        'type': 'password',
                                        'username': username,
                                        'password': password,
                                        'tags': ['jboss'],
                                    }
                                    DB.insert_credential(cred_info)

                    except KeyError:
                        pass
            elif url in auth_5_6_urls:
                if res['code'] in [200] and 'jboss' in res['title'].lower():
                    Output.highlight({'target': http.url(full_url), 'message': 'JBoss interface'})

                    form = None
                    for f in res['forms']:
                        if not 'name' in f:
                            continue

                        if 'login_form' in f['name'].lower():
                            form = f
                            break

                    if not form:
                        Output.error({'target': http.url(full_url), 'message': 'Unable to find JBoss authentication form'})
                    else:
                        if args['bruteforce']:
                            Output.highlight({'target': http.url(full_url), 'message': 'Starting bruteforce...'})
                            for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                                username, password = cred.split(':')

                                data = http.get(full_url)

                                if not data:
                                    continue

                                form = None
                                for f in data['forms']:
                                    if not 'name' in f:
                                        continue

                                    if 'login_form' in f['name'].lower():
                                        form = f
                                        break

                                if not form:
                                    continue

                                for arg in form['args']:
                                    if 'login_form:name' in arg.lower():
                                        form['args'][arg] = username

                                    if 'login_form:password' in arg.lower():
                                        form['args'][arg] = password

                                res = http.send_form(full_url, form, html=data['html'], cookies=data['cookies'])

                                after_auth_form = None
                                for f in res['forms']:
                                    if not 'name' in f:
                                        continue

                                    if 'login' in f['name'].lower():
                                        after_auth_form = f
                                        break

                                if after_auth_form != None:
                                    continue

                                Output.success({'target': http.url(full_url), 'message': 'Authentication success to PhpMyAdmin with login %s and password %s' % (username, password)})

                                cred_info = {
                                    'hostname': target['hostname'],
                                    'port': target['port'],
                                    'service': 'http',
                                    'url': http.url(full_url),
                                    'type': 'password',
                                    'username': username,
                                    'password': password,
                                    'tags': ['jboss'],
                                }
                                DB.insert_credential(cred_info)

                                vuln_info = {
                                    'hostname': target['hostname'],
                                    'port': target['port'],
                                    'service': 'http',
                                    'url': http.url(full_url),
                                    'name': 'Default or predictable credentials on JBoss service',
                                    'description': 'JBoss %s possess the following default or weak credentials: %s:%s' % (http.url(full_url), username, password),
                                }
                                DB.insert_vulnerability(vuln_info)

            elif url in auth_7_8_urls:
                if res['code'] in [200]:
                    # Looks good, now /management should be a 401

                    management_url = urljoin(res['response_url'], '/management')

                    res_management = http.get(management_url)

                    if res_management['code'] in [401]:

                        Output.write({'target': http.url(target['path']), 'message': 'JBoss interface'})

                        try:
                            auth_type = res_management['auth_type']

                            if args['bruteforce']:
                                Output.highlight({'target': http.url(full_url), 'message': 'Starting bruteforce...'})
                                for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                                    username, password = cred.split(':')

                                    res_management = http.get(management_url, auth=(auth_type, username, password))

                                    if res_management['code'] in [200]:
                                        Output.success({'target': http.url(full_url), 'message': 'Authentication success with login %s and password %s' % (username, password)})

                                        cred_info = {
                                            'hostname': target['hostname'],
                                            'port': target['port'],
                                            'service': 'http',
                                            'url': http.url(full_url),
                                            'type': 'password',
                                            'username': username,
                                            'password': password,
                                            'tags': ['jboss'],
                                        }
                                        DB.insert_credential(cred_info)

                                        vuln_info = {
                                            'hostname': target['hostname'],
                                            'port': target['port'],
                                            'service': 'http',
                                            'url': http.url(full_url),
                                            'name': 'Default or predictable credentials on JBoss service',
                                            'description': 'JBoss %s possess the following default or weak credentials: %s:%s' % (http.url(full_url), username, password),
                                        }
                                        DB.insert_vulnerability(vuln_info)




                        except KeyError:
                            pass


