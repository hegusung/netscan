import os.path
from urllib.parse import urljoin

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

class Module:
    name = 'Robots'
    description = 'Search for robots.txt file'

    def run(self, target, args, useragent, proxy, timeout):
        googlebot_useragent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

        http = HTTP(target['method'], target['hostname'], target['port'], googlebot_useragent, proxy, timeout)

        response = http.get('/robots.txt')
        if response and response['code'] in [200]:

            Output.write({'target': http.url('/robots.txt'), 'message': 'robots.txt present'})

            http_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'http',
                'url': http.url('/robots.txt'),
                'http': {
                    'path': '/robots.txt',
                    'code': response['code'],
                    'server': response['server'],
                    'title': response['title'],
                    'content-type': response['content-type'],
                },
            }
            DB.insert_http_url(http_info)

            uri_list = []
            for line in response["html"].split('\n'):
                line = line.strip()
                items = line.split()

                if len(items) > 0 and items[-1].startswith("/"):
                    uri = items[-1].split('?')[0].split('&')[0].strip()
                    if len(uri) != 0:
                        uri_list.append(uri)
            uri_list = list(set(uri_list))

            for uri in uri_list:
                if '*' in uri:
                    continue

                output = http.get(uri)

                if output['code'] in [404]:
                    continue

                http_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'protocol': 'tcp',
                    'service': 'http',
                    'url': http.url(uri),
                    'http': {
                        'path': uri,
                        'code': output['code'],
                        'server': output['server'],
                        'title': output['title'],
                        'content-type': output['content-type'],
                    },
                }
                DB.insert_http_url(http_info)

                output['message_type'] = 'http'
                output['target'] = http.url(uri)
                Output.write(output)
