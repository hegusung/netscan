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
            ('html.lower', ['.*class\\:.*', '.*param\\:.*']),
        ],
    },
    {
        'system': 'backupfiles',
        'urls': ['_FILE_.bak', '_FILE_~', '._FILE_.swp', '%23_FILE_%23'],
        'replace': ['wp-config.php', 'configuration.php', 'config.php', 'config.inc.php', 'settings.php'],
        'filters': [
            ('code', 200),
            ('title', '^N/A$'),
            ('html.lower', ['<\\?php', '<=\\?']),
        ],
    },
    {
        'system': 'docker',
        'urls': ['Dockerfile'],
        'filters': [
            ('code', 200),
            ('title', '^N/A$'),
            ('!html.lower', '<!doctype html>'),
            ('!html.lower', '.*The requested URL was not found on the web server\\..*'),
            ('!content-type', '^text/html$'),
            ('!content-type', '^application/json$'),
        ],
    },
    {
        'system': 'cicd',
        'urls': [
            ".github/workflows/deploy.yml",
            ".github/workflows/ci.yml",
            ".gitlab-ci.yml",
            ".travis.yml",
        ],
        'filters': [
            ('code', 200),
        ],
    },
    {
        'system': 'cloud',
        'urls': [
            ".aws/.env",
            ".aws/credentials",
            ".aws/credentials.bak",
            ".aws/config",
            ".boto",
            ".s3cfg",
            ".amplifyrc",
            ".docker/config.json",
            ".docker/.env",
            ".docker/laravel/app/.env",
            ".dockercfg",
        ],
        'filters': [
            ('code', 200),
        ],
    },
    {
        'system': 'config',
        'urls': [
            "vite.config.js",
            "wp-config.txt",
            "config.php",
            "config.env",
            "config.json",
            "config.yaml",
            "config/aws.yml",
            "app.config.js",
            "config.js",
            "config/config.js",
            "env-config.js",
            "runtime-config.js",
        ],
        'filters': [
            ('code', 200),
        ],
    },
    {
        'system': 'dotenv',
        'urls': [
            ".env",
            ".env-example",
            ".env-sample",
            ".env.aws",
            ".env.anthropic",
            ".env.bak",
            ".env.dev",
            ".env.dist",
            ".env.live",
            ".env.local",
            ".env.docker",
            ".env.example",
            ".env.old",
            ".env.openai",
            ".env.php",
            ".env.prod",
            ".env.production",
            ".env.sample",
            ".env.staging",
            ".env.save",
            ".env~",
            ".env.test",
            ".env.swp",
            ".env.testing",
            ".env.development",
            ".env.backup",
            ".env.omnisend",
            ".env.getresponse",
            ".env.activecampaign",
            ".env.convertkit",
            ".env_production",
            ".env_local",
            "api/.env",
            "admin/.env",
            "app/.env",
            "application/.env",
            "back/.env",
            "backend/.env",
            "backup/.env",
            "cms/.env",
            "config/.env",
            "core/.env",
            "demo/.env",
            "dev/.env",
            "frontend/.env",
            "media/.env",
            "laravel/.env",
            "old/.env",
            "new/.env",
            "production/.env",
            "public/.env",
            "server/.env",
            "src/.env",
            "test/.env",
            "staging/.env",
            "v1/.env",
            "v2/.env",
            "web/.env",
            "conf/.env",
            "settings/.env",
            "prefs/.env",
            "options/.env",
            "params/.env",
            "vars/.env",
            "environment/.env",
            "environments/.env",
            "user-data/.env",
            "user/.env",
            "vendor/.env",
            "root/.env",
            "master/.env",
            "main/.env",
            "primary/.env",
            "secondary/.env",
            "bak/.env",
            "tmp/.env",
            "website/.env.staging",
            "website/.env.local",
            "backend/.env.local",
            "api/.env.local",
        ],
        'filters': [
            ('code', 200),
            ('title', '^N/A$'),
            ('!html.lower', '<!doctype html>'),
            ('!html.lower', '<html>'),
            ('!html.lower', '<body>'),
            ('!html.lower', '.*The requested URL was not found on the web server\\..*'),
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
            ('!html.lower', '.*The requested URL was not found on the web server\\..*'),
        ],
    },

]

class Module:
    name = 'Secrets'
    description = 'Search for secrets in specific files [Experimental]'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        Output.minor({'target': http.url(target['path']), 'message': '[%s] Running module...' % self.name})

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
                'host': target['hostname'],
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

