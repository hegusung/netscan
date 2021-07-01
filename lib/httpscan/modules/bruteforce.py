import os.path
import re

from utils.output import Output
from utils.db import DB
from utils.utils import gen_random_string, gen_bruteforce_creds, gen_bruteforce_creds
from utils.parsers import *
from lib.httpscan.http import HTTP

creds = [
    'admin:admin',
    'root:root',
]

auth_form_pattern = re.compile('.*login.*', re.IGNORECASE)
username_input_pattern = re.compile('.*(username|name|login).*', re.IGNORECASE)
password_input_pattern = re.compile('.*(password|pass).*', re.IGNORECASE)

class Module:
    name = 'Bruteforce'
    description = 'Discover and bruteforce authentication forms'

    def run(self, target, args, useragent, proxy, timeout, safe):
        http = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout)

        res = http.get(target['path'])

        if res['code'] in [200]:

            form = None
            for f in res['forms']:
                if 'name' in f and auth_form_pattern.match(f['name']):
                    form = f
                    break

                if 'id' in f and auth_form_pattern.match(f['id']):
                    form = f
                    break

            if not form:
                return
            else:
                # bruteforce login form
                http_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'protocol': 'tcp',
                    'service': 'http',
                    'url': http.url(target['path']),
                    'http': {
                        'path': target['path'],
                        'code': res['code'],
                        'server': res['server'],
                        'title': res['title'],
                        'content-type': res['content-type'],
                    },
                    'tags': ['authentication_form']
                }
                DB.insert_http_url(http_info)

                Output.highlight({'target': http.url(target['path']), 'message': 'Authentication form'})

                if args['bruteforce'] != None:
                    Output.highlight({'target': http.url(target['path']), 'message': 'Starting bruteforce...'})
                    for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                        username, password = cred.split(':')

                        data = http.get(target['path'])

                        if not data:
                            continue

                        form = None
                        for f in data['forms']:
                            if 'name' in f and auth_form_pattern.match(f['name']):
                                form = f
                                break

                            if 'id' in f and auth_form_pattern.match(f['id']):
                                form = f
                                break

                        if not form:
                            continue

                        user_found = False
                        pass_found = False
                        for arg in form['args']:
                            if username_input_pattern.match(arg):
                                form['args'][arg] = username
                                user_found = True

                            if password_input_pattern.match(arg):
                                form['args'][arg] = password
                                pass_found = True

                        if not user_found:
                            Output.error({'target': http.url(target['path']), 'message': 'Unable to find username field'})
                            return
                        elif not pass_found:
                            Output.error({'target': http.url(target['path']), 'message': 'Unable to find password field'})
                            return

                        headers = {
                            'Referer': data['response_url'],
                        }

                        res = http.send_form(data['response_url'], form, html=data['html'], cookies=data['cookies'], headers=headers)

                        after_auth_form = None
                        for f in res['forms']:
                            if 'name' in f and auth_form_pattern.match(f['name']):
                                after_auth_form = f
                                break

                            if 'id' in f and auth_form_pattern.match(f['id']):
                                after_auth_form = f
                                break

                        if after_auth_form != None:
                            continue

                        Output.success({'target': http.url(target['path']), 'message': 'Authentication success with login %s and password %s' % (username, password)})

                        cred_info = {
                            'hostname': target['hostname'],
                            'port': target['port'],
                            'service': 'http',
                            'url': http.url(target['path']),
                            'type': 'password',
                            'username': username,
                            'password': password,
                        }
                        DB.insert_credential(cred_info)
        elif res['code'] in [401]:
            # bruteforce login form
            http_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'http',
                'url': http.url(target['path']),
                'http': {
                    'path': target['path'],
                    'code': res['code'],
                    'server': res['server'],
                    'title': res['title'],
                    'content-type': res['content-type'],
                },
                'tags': ['authentication_form']
            }
            DB.insert_http_url(http_info)
            Output.highlight({'target': http.url(target['path']), 'message': 'Authentication form'})

            if args['bruteforce'] != None:
                Output.highlight({'target': http.url(target['path']), 'message': 'Starting bruteforce...'})
                try:
                    auth_type = res['auth_type']

                    for cred in gen_bruteforce_creds(args['bruteforce'], creds):
                        username, password = cred.split(':')

                        output = http.get(target['path'], auth=(auth_type, username, password))

                        if output['code'] in [200]:
                            Output.success({'target': http.url(target['path']), 'message': 'Authentication success with login %s and password %s' % (username, password)})

                            cred_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'service': 'http',
                                'url': http.url(target['path']),
                                'type': 'password',
                                'username': username,
                                'password': password,
                            }
                            DB.insert_credential(cred_info)

                except KeyError:
                    pass

