import os.path

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

class Module:
    name = 'Headers'
    description = 'Check the security headers of a specific web application'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        res = http.get(target['path'])
        
        headers = res['headers']

        headers_vuln = []
        headers_txt = "Security headers:\n"

        # Check Strict-Transport-Security
        if not "Strict-Transport-Security" in headers:
            headers_vuln.append({
                'Strict-Transport-Security': 'Missing Strict-Transport-Security header, an attacker could request the browser specific APIs',
            })
        else:
            headers_txt += " "*26 + "Strict-Transport-Security: %s\n" % headers['Strict-Transport-Security']

        # Check CSP
        if not "Content-Security-Policy" in headers:
            headers_vuln.append({
                'Content-Security-Policy': 'Missing Content-Security-Policy header, protects against XSS attacks',
            })
        else:
            headers_txt += " "*26 + "Content-Security-Policy: %s\n" % headers['Content-Security-Policy']

        # Check X-Frame-Options
        if not "X-Frame-Options" in headers:
            headers_vuln.append({
                'X-Frame-Options': 'Missing X-Frame-Options header, protects against Clickjacking',
            })
        else:
            headers_txt += " "*26 + "X-Frame-Options: %s\n" % headers['X-Frame-Options']

            if not headers['X-Frame-Options'] in ["SAMEORIGIN", "DENY"]:
                headers_vuln.append({
                    'X-Frame-Options': 'X-Frame-Options: Non-recommended value: %s, it should be "SAMEORIGIN"' % headers['X-Frame-Options'],
                })

        # Check X-Content-Type-Options
        if not "X-Content-Type-Options" in headers:
            headers_vuln.append({
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header, forces the browser to stick with the declared Content-Type',
            })
        else:
            headers_txt += " "*26 + "X-Content-Type-Options: %s\n" % headers['X-Content-Type-Options']

            if headers['X-Content-Type-Options'] != "nosniff":
                headers_vuln.append({
                    'X-Content-Type-Options': 'X-Content-Type-Options: Bad header value: %s, it should be "nosniff"' % headers['X-Content-Type-Options'],
                })

        # Check Referrer-Policy
        if not "Referrer-Policy" in headers:
            headers_vuln.append({
                'Referrer-Policy': 'Missing Referrer-Policy header, the website users confidentiality is not assured (could be defined in a <meta> or in the CSP)',
            })
        else:
            headers_txt += " "*26 + "Referrer-Policy: %s\n" % headers['Referrer-Policy']

            if headers['Referrer-Policy'] in ['']:
                headers_vuln.append({
                    'Referrer-Policy': 'Referrer-Policy: Empty Referrer-Policy header, the website users confidentiality is not assured (could be defined in a <meta> or in the CSP)',
                })
            elif headers['Referrer-Policy'] in ['unsafe-url']:
                headers_vuln.append({
                    'Referrer-Policy': 'Referrer-Policy: Non-recommended value: %s, consider using "strict-origin-when-cross-origin"' % headers['Referrer-Policy'],
                })
            elif headers['Referrer-Policy'] in ['origin']:
                headers_vuln.append({
                    'Referrer-Policy': 'Referrer-Policy: Non-recommended value: %s, consider using "strict-origin"' % headers['Referrer-Policy'],
                })
            elif headers['Referrer-Policy'] in ['origin-when-cross-origin']:
                headers_vuln.append({
                    'Referrer-Policy': 'Referrer-Policy: Non-recommended value: %s, consider using "strict-origin-when-cross-origin"' % headers['Referrer-Policy'],
                })

        # Check Permissions-Policy
        if not "Permissions-Policy" in headers:
            headers_vuln.append({
                'Permissions-Policy': 'Missing Permissions-Policy header, an attacker could request the browser specific APIs',
            })
        else:
            headers_txt += " "*26 + "Permissions-Policy: %s\n" % headers['Permissions-Policy']

        Output.highlight({'target': http.url(target['path']), 'message': headers_txt})

        vuln_txt = "Unsecure security header configuration on %s:\n" % http.url(target['path'])
        for item in headers_vuln:
            for key, value in item.items():
                vuln_txt += " "*26 + "%s\n" % value

        vuln_info = {
            'hostname': target['hostname'],
            'port': target['port'],
            'service': 'http',
            'url': http.url(target['path']),
            'name': 'Missing security headers',
            'description': vuln_txt,
        }
        DB.insert_vulnerability(vuln_info)

        Output.vuln({'target': http.url(target['path']), 'message': vuln_txt})


