import os.path
from urllib.parse import urljoin

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

repo_dict = {
    "git": ".git/HEAD",
    "mercurial": ".hg/branch",
    "svn": ".svn/entries",
}

class Module:
    name = 'Repo'
    description = 'Search for accessible repositories (git, mercurial, svn)'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        for repo, url in repo_dict.items():

            check_url_list = []
            if target['path'].endswith('/'):
                check_url_list.append(os.path.join(target['path'], url))
            else:
                check_url_list.append(os.path.join(target['path'], url))
                check_url_list.append(os.path.join(os.path.dirname(target['path']), url))

            for check_url in check_url_list:
                response = http.get(check_url)

                if response and response['code'] in [200] and response['title'] == 'N/A' and response['content-type'] == None:

                    Output.vuln({'target': http.url(check_url), 'message': '%s depot accessible' % repo})

                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'http',
                        'url': http.url(check_url),
                        'name': 'Repository accessible though HTTP',
                        'description': 'Repository accessible at : %s' % http.url(check_url),
                    }
                    DB.insert_vulnerability(vuln_info)

