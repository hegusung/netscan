import traceback
import socket
from .ftp import FTPScan
from .ftp_bruteforce import *

from utils.output import Output
from utils.dispatch import dispatch
from utils.utils import sizeof_fmt
from utils.db import DB

def ftpscan_worker(target, actions, creds, timeout):
    try:
        ftpscan = FTPScan(target['hostname'], target['port'], timeout)

        ftp_code, version = ftpscan.grab_banner()
        if ftp_code:
            Output.write({'target': ftpscan.url(), 'message': '%d   %s' % (ftp_code, version)})
            DB.insert_port({
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'ftp',
                'version': version,
            })

            if 'username' in creds and 'password' in creds:
                success = ftpscan.auth(creds['username'], creds['password'])
            else:
                success = ftpscan.auth()
            if success:
                if 'username' in creds and 'password' in creds:
                    Output.success({'target': ftpscan.url(), 'message': 'Successful connection with credentials %s:%s' % (creds['username'], creds['password'])})
                    cred_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'ftp',
                        'url': ftpscan.url(),
                        'type': 'password',
                        'username': creds['username'],
                        'password': creds['password'],
                    }
                    DB.insert_credential(cred_info)

                else:
                    Output.vuln({'target': ftpscan.url(), 'message': 'Successful anonymous connection'})
                    vuln_info = {
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'service': 'ftp',
                        'url': ftpscan.url(),
                        'name': 'Anonymous connection to service',
                        'description': 'Anonymous account can connect to ftp service: %s' % ftpscan.url(),
                    }
                    DB.insert_vulnerability(vuln_info)

                if 'list' in actions:
                    try:
                        ftp_dir = '/'
                        contents = ""
                        for content in ftpscan.list_content(ftp_dir, recurse=actions['list']['recurse']):
                            # Display output
                            if 'size' in content:
                                contents += " "*60+"- %s %s\n" % (content['name'].ljust(30), sizeof_fmt(content['size']))
                            else:
                                contents += " "*60+"- %s\n" % content['name']

                            if 'username' in creds:
                                account = creds['username']
                            else:
                                account = 'anonymous'

                            # Add to database
                            content_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'url': ftpscan.url(),
                                'service': 'ftp',
                                'path': content['name'],
                                'account': account,
                            }
                            if 'size' in content:
                                content_info['size'] = content['size']
                            if 'username' in creds and 'password' in creds:
                                content_info['share'] = creds['username']
                            else:
                                content_info['share'] = 'anonymous'
                            DB.insert_content(content_info)
                        Output.highlight({'target': ftpscan.url(), 'message': 'Contents of %s\n%s' % (ftp_dir, contents)})
                    except socket.timeout as e:
                        Output.error({'target': ftpscan.url(), 'message': 'Timeout while listing folder, do you have a firewall enabled ?'})


        if 'bruteforce' in actions:
            if 'username_file' in actions['bruteforce'] != None:
                Output.write({'target': ftpscan.url(), 'message': 'Starting bruteforce:'})

                username_file = actions['bruteforce']['username_file']
                password_file = actions['bruteforce']['password_file'] if 'password_file' in actions['bruteforce'] else None
                bruteforce_workers = actions['bruteforce']['workers']

                # The generator will provide a username:password_list couple
                gen = bruteforce_generator(target, username_file, password_file)
                gen_size = bruteforce_generator_count(target, username_file, password_file)

                args = (timeout,)
                dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])


    except Exception as e:
        Output.write({'target': ftpscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        ftpscan.disconnect()

