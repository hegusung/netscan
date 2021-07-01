import os.path
from copy import copy
from urllib.parse import urljoin
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

class Module:
    name = 'Filesystem'
    description = 'Search for web servers making their filesystem accessible and crawl'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        self.search_filesystem(target, http, target['path'])

    def search_filesystem(self, target, http, path, recurse=3):
        if recurse < 0:
            return

        data = http.get(path)

        current_url = http.url(path)

        if data["code"] in [200] and (data["title"].lower().startswith("index of ")):
            soup = BeautifulSoup(data["html"], "html.parser")

            if target['path'] == path:
                Output.highlight({'target': http.url(path), 'message': 'HTTP server sharing its filesystem found, enumerating to db...'})

                # Add to database
                content_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'url': '%s://%s:%d' % (target['method'], target['hostname'], target['port']),
                    'service': 'http',
                    'path': path,
                }
                content_info['share'] = 'N/A'
                DB.insert_content(content_info)


            for link in soup.findAll('a', href=True):
                url = urljoin(current_url, link['href']).split('?')[0]

                if url in current_url:
                    # link to current directory or directory under, exclude
                    continue

                o = urlparse(url)

                # Add to database
                content_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'url': '%s://%s:%d' % (target['method'], target['hostname'], target['port']),
                    'service': 'http',
                    'path': o.path,
                }
                content_info['share'] = 'N/A'
                DB.insert_content(content_info)

                next_path = o.path
                self.search_filesystem(target, http, next_path, recurse=recurse-1)
