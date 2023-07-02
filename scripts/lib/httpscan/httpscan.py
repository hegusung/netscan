from time import sleep
import os.path
import OpenSSL

from .http import HTTP

from utils.output import Output
from utils.dispatch import dispatch
from .dir_bruteforce import dir_file_count, dir_bruteforce_generator
from utils.db import DB
from utils.utils import gen_random_string
from utils.modulemanager import ModuleManager

http_modules = ModuleManager('lib/httpscan/modules')

def httpscan_worker(target, verb, data, actions, useragent, header_dict, http_auth, cookie_dict, proxy, dir_bruteforce, extensions, dir_bruteforce_workers, timeout, excluded_code=[], inexistant_url=[], ignore_cert=True):
    try:
        httpscan = HTTP(target['method'], target['hostname'], target['port'], useragent, proxy, timeout, headers=header_dict, auth=http_auth, cookies=cookie_dict)

        if verb == 'GET':
            output = httpscan.get(target['path'], params=target['params'] if 'params' in target else None)
        elif verb == 'POST':
            output = httpscan.post(target['path'], data, params=target['params'] if 'params' in target else None)
        if output != None and not output['code'] in excluded_code:

            for inex in inexistant_url:
                for key in inex:
                    if output[key] != inex[key]:
                        break
                else:
                    return

            output['message_type'] = 'http'
            output['target'] = httpscan.url(target['path'], params=target['params'] if 'params' in target else None)
            Output.write(output)
            db_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'http',
                'version': output['server'],
            }
            if 'params' in target:
                db_info['params'] = target['params']
            service_info = {}

            if httpscan.method == 'https' and not ignore_cert:
                try:
                    names = httpscan.get_cert_hostnames()
                    if len(names) != 0:
                        Output.write({"target": httpscan.url(target['path']), "message": "certificates names: %s" % ", ".join(names)})
                        service_info['cert_names'] = names
                        # TODO: resolve name and insert them in ES

                    service_info['ssl'] = True
                except OpenSSL.SSL.Error:
                    pass

            db_info['service_info'] = service_info
            DB.insert_port(db_info)

            # Insert http info
            # TODO: insert redirection url also if there is one
            http_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'http',
                'url': httpscan.url(target['path']),
                'http': {
                    'path': target['path'],
                    'code': output['code'],
                    'server': output['server'],
                    'title': output['title'],
                    'content-type': output['content-type'],
                }
            }
            DB.insert_http_url(http_info)

            if 'modules' in actions or dir_bruteforce:
                ignored_code = None
                safe = True
                # Try a random uri first to prevent false positives
                random_uri = os.path.join(target['path'], gen_random_string())
                output = httpscan.get(random_uri)

                if output != None and output['code'] in [200, 401, 503]:
                    safe = False
                if output != None:
                    ignored_code = output['code']

            if 'modules' in actions:
                http_modules.execute_modules(actions['modules']['modules'], (target, actions['modules']['args'], useragent, proxy, timeout, safe))

            if dir_bruteforce:
                if not safe:
                    Output.highlight({"target": httpscan.url(target['path']), "message": "Directory bruteforce aborted because this server will generate a lot of false positives"})

                    random_uri = os.path.join(target['path'], gen_random_string())
                    inexistant_url = []
                    for ext in ['', '.html']:
                        output = httpscan.get(random_uri)
                        inexistant_url.append({
                            'code': output['code'],
                            'content-type': output['content-type'],
                            'server': output['server'],
                            'title': output['title'],
                        })
                        
                    extension_list = ['']
                    if extensions != None:
                        extension_list += extensions.split(',')
                        extension_list = list(set(extension_list))

                    gen = dir_bruteforce_generator(target, dir_bruteforce, extension_list)
                    gen_size = dir_file_count(dir_bruteforce)*len(extension_list)

                    excluded_code_arg = [400, 404]
                    if ignored_code != None:
                        excluded_code_arg.append(ignored_code)

                    args = ({}, useragent, header_dict, http_auth, cookie_dict, proxy, None, extensions, dir_bruteforce_workers, timeout, excluded_code_arg, inexistant_url, True)
                    dispatch(gen, gen_size, httpscan_worker, args, workers=dir_bruteforce_workers, process=False, pg_name=httpscan.url(target['path'])) 


                else:
                    extension_list = ['']
                    if extensions != None:
                        extension_list += extensions.split(',')
                        extension_list = list(set(extension_list))

                    gen = dir_bruteforce_generator(target, dir_bruteforce, extension_list)
                    gen_size = dir_file_count(dir_bruteforce)*len(extension_list)

                    excluded_code_arg = [400, 404]
                    if ignored_code != None:
                        excluded_code_arg.append(ignored_code)

                    args = ({}, useragent, header_dict, http_auth, cookie_dict, proxy, None, extensions, dir_bruteforce_workers, timeout, excluded_code_arg, []), True
                    dispatch(gen, gen_size, httpscan_worker, args, workers=dir_bruteforce_workers, process=False, pg_name=httpscan.url(target['path'])) 
    except ConnectionRefusedError:
        pass
