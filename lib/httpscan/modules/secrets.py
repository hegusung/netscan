import os.path
import re
from copy import copy
from urllib.parse import urljoin

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds
from lib.httpscan.http import HTTP

secrets = [
    {
        'system': 'symphony',
        'urls': [
            'config/databases.yml'
        ],
        'filters': [
            ('code', 200),
            ('title', '^N/A$'),
            ('html.lower', ['.*class\:.*', '.*param\:.*']),
        ],
    },
    {
        'system': 'backupfiles',
        'urls': ['_FILE_.bak', '_FILE_~', '._FILE_.swp', '%23_FILE_%23'],
        'replace': ['wp-config.php', 'configuration.php', 'config.php', 'config.inc.php', 'settings.php'],
        'filters': [
            ('code', 200),
            ('title', '^N/A$'),
            ('html.lower', ['<\?php', '<=\?']),
        ],
    },
    {
        'system': 'docker',
        'urls': ['Dockerfile'],
        'filters': [
            ('code', 200),
            ('title', '^N/A$'),
            ('!html.lower', '<!doctype html>'),
            ('!content-type', '^text/html$'),
            ('!content-type', '^application/json$'),
        ],
    },
    {
        'system': 'dotenv',
        'urls': ['.env'],
        'filters': [
            ('code', 200),
            ('title', '^N/A$'),
            ('!html.lower', '<!doctype html>'),
            ('!html.lower', '<html>'),
            ('!html.lower', '<body>'),
            ('!html.len', 0),
            ('!content-type', '^text/html$'),
            ('!content-type', '^application/json$'),
        ],
    },
    {
        'system': 'sqlite_database',
        'urls': ['sqlite3.db', 'sqlite.db', 'db.sqlite3', 'db.sqlite'],
        'filters': [
            ('code', 200),
            ('title', '^N/A$'),
            ('html', '^SQLite'),
        ],
    },
    {
        'system': 'sql_dump',
        'urls': ['_FILE_'],
        'replace': ['dump.sql', 'database.sql', '1.sql', 'backup.sql', 'data.sql','db_backup.sql', 'dbdump.sql', 'db.sql', 'localhost.sql','mysql.sql', 'site.sql', 'sql.sql', 'temp.sql', 'users.sql','translate.sql', 'mysqldump.sql'],
        'filters': [
            ('code', 200),
            ('html.lower', 'insert '),
            ('html.lower', 'into '),
            ('html.lower', 'create '),
        ],
    },
    {
        'system': 'sql_dump',
        'urls': ['_FILE_.gz', '_FILE_.zip', '_FILE_.bz2', '_FILE_.xz'],
        'replace': ['dump.sql', 'database.sql', '1.sql', 'backup.sql', 'data.sql','db_backup.sql', 'dbdump.sql', 'db.sql', 'localhost.sql','mysql.sql', 'site.sql', 'sql.sql', 'temp.sql', 'users.sql','translate.sql', 'mysqldump.sql'],
        'filters': [
            ('code', 200),
            ('title', '^N/A$'),
            ('!html.lower', '<!doctype html>'),
            ('!html.lower', '<html>'),
            ('!content-type', '^text/html$'),
            ('!content-type', '^application/json$'),
        ],
    },

]

class Module:
    name = 'Secrets'
    description = 'Search for secrets in specific files'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        for secret in secrets:
            for url in secret['urls']:
                if 'replace' in secret:
                    for r in secret['replace']:
                        r_url = url.replace('_FILE_', r)
                        output = http.get(os.path.join(target['path'], r_url))

                        self.process(target, http, os.path.join(target['path'], r_url), output, secret)
                else:
                    output = http.get(os.path.join(target['path'], url))

                    self.process(target, http, os.path.join(target['path'], url), output, secret)

    def process(self, target, http, url, output, secret):
        if output == None:
            return

        system = secret['system']
        filters = secret['filters']

        success = True
        for f in filters:
            key = f[0]
            if not type(f[1]) == list:
                filter = [f[1]]
            else:
                filter = f[1]

            if key.startswith('!'):
                invert = True
                key = key[1:]
            else:
                invert = False

            lower = False
            if key.endswith('.lower'):
                lower = True
                key = key[:-6]

            str_len = False
            if key.endswith('.len'):
                str_len = True
                key = key[:-4]

            value = output[key]

            if value == None:
                if invert:
                    #the value doesn't exist, but we need it NOT to be a certain value... so continue
                    continue
                else:
                    #the value doesn't exist, but we need it to BE a certain value... so it's a fail
                    success = False
                    break

            if lower:
                value = value.lower()
            if str_len:
                value = len(value)

            check = any(re.search(p, value) != None if type(p) == str else p == value for p in filter)

            if invert:
                check = not check

            if not check:
                success = False
                break

        if success:
            http_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'http',
                'url': http.url(url),
                'http': {
                    'path': url,
                    'code': output['code'],
                    'server': output['server'],
                    'title': output['title'],
                    'content-type': output['content-type'],
                },
                'tags': [system],
            }
            DB.insert_http_url(http_info)

            output['message_type'] = 'http'
            output['target'] = http.url(url)
            Output.highlight(output)

