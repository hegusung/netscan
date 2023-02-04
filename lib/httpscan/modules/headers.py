import os.path
from bs4 import BeautifulSoup

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
        header_content = check_header("Strict-Transport-Security", headers, res['html'])
        if not header_content:
            headers_vuln.append({
                'Strict-Transport-Security': 'Missing Strict-Transport-Security header, an attacker could request the browser specific APIs',
            })
        else:
            headers_txt += " "*26 + "Strict-Transport-Security: %s\n" % header_content

        # Check CSP
        header_content = check_header("Content-Security-Policy", headers, res['html'])
        if not header_content:
            headers_vuln.append({
                'Content-Security-Policy': 'Missing Content-Security-Policy header, protects against XSS attacks',
            })
        else:
            headers_txt += " "*26 + "Content-Security-Policy: %s\n" % header_content

        # Check X-Frame-Options
        header_content = check_header("X-Frame-Options", headers, res['html'])
        if not header_content:
            headers_vuln.append({
                'X-Frame-Options': 'Missing X-Frame-Options header, protects against Clickjacking',
            })
        else:
            headers_txt += " "*26 + "X-Frame-Options: %s\n" % header_content

            if not header_content in ["SAMEORIGIN", "DENY"]:
                headers_vuln.append({
                    'X-Frame-Options': 'X-Frame-Options: Non-recommended value: %s, it should be "SAMEORIGIN"' % header_content,
                })

        # Check X-Content-Type-Options
        header_content = check_header("X-Content-Type-Options", headers, res['html'])
        if not header_content:
            headers_vuln.append({
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header, forces the browser to stick with the declared Content-Type',
            })
        else:
            headers_txt += " "*26 + "X-Content-Type-Options: %s\n" % header_content

            if header_content != "nosniff":
                headers_vuln.append({
                    'X-Content-Type-Options': 'X-Content-Type-Options: Bad header value: %s, it should be "nosniff"' % header_content,
                })

        # Check Referrer-Policy
        header_content = check_header("Referrer-Policy", headers, res['html'])
        if not header_content:
            headers_vuln.append({
                'Referrer-Policy': 'Missing Referrer-Policy header, the website users confidentiality is not assured (could be defined in a <meta> or in the CSP)',
            })
        else:
            headers_txt += " "*26 + "Referrer-Policy: %s\n" % header_content

            if header_content in ['']:
                headers_vuln.append({
                    'Referrer-Policy': 'Referrer-Policy: Empty Referrer-Policy header, the website users confidentiality is not assured (could be defined in a <meta> or in the CSP)',
                })
            elif header_content in ['unsafe-url']:
                headers_vuln.append({
                    'Referrer-Policy': 'Referrer-Policy: Non-recommended value: %s, consider using "strict-origin-when-cross-origin"' % header_content,
                })
            elif header_content in ['origin']:
                headers_vuln.append({
                    'Referrer-Policy': 'Referrer-Policy: Non-recommended value: %s, consider using "strict-origin"' % header_content,
                })
            elif header_content in ['origin-when-cross-origin']:
                headers_vuln.append({
                    'Referrer-Policy': 'Referrer-Policy: Non-recommended value: %s, consider using "strict-origin-when-cross-origin"' % header_content,
                })

        # Check Permissions-Policy

        header_content = check_header("Permissions-Policy", headers, res['html'])
        if not header_content:
            headers_vuln.append({
                'Permissions-Policy': 'Missing Permissions-Policy header, an attacker could request the browser specific APIs',
            })
        else:
            headers_txt += " "*26 + "Permissions-Policy: %s\n" % header_content

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

def check_header(header_name, headers, html):

    if header_name in headers:
        return headers[header_name]

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.findAll('meta'):
        if tag.get('http-equiv') != None and tag['http-equiv'].lower() == header_name.lower():
            return tag['content']
    else:
        return None
