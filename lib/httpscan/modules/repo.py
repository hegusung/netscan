import os.path
from copy import copy
from urllib.parse import urljoin

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

repo_urls = {
    'Git': '.git/HEAD',
    'Hg': '.hg/branch',
    'SVN': '.svn/entries',
}

class Module:
    name = 'Repo'
    description = 'Search for accessible repositories files (git, hg and svn)'

    def run(self, target, args, useragent, proxy, timeout):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        discovered = {}
        for repo, url in repo_urls.items():

            output = http.get(os.path.join(target['path'], url))
            if output and output['code'] in [200] and output['title'] == 'N/A':
                discovered[repo] = {'url': url, 'output': copy(output)}

        # If all 3 discovered it is likely a false positive
        if len(discovered.keys()) == 1:
            for repo in discovered:
                url = discovered[repo]['url']
                output = discovered[repo]['output']

                Output.write({'target': http.url(os.path.join(target['path'], url)), 'message': '%s repository accessible' % repo})

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
                    'tags': ['repository']
                }
                DB.insert_http_url(http_info)

                vuln_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'http',
                    'url': http.url(os.path.join(target['path'], url)),
                    'name': 'Repository files accessible from web server',
                    'description': 'Files from the %s repository are accessible at %s' % (repo, http.url(os.path.join(target['path'], url))),
                }
                DB.insert_vulnerability(vuln_info)

