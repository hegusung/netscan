import traceback
import socket
from .ftp import FTPScan
from .ftp_bruteforce import *

from utils.output import Output
from utils.dispatch import dispatch

def ftpscan_worker(target, actions, creds, timeout):
    try:
        ftpscan = FTPScan(target['hostname'], target['port'], timeout)

        ftp_code, version = ftpscan.grab_banner()
        if ftp_code:
            Output.write({'target': ftpscan.url(), 'message': '%d   %s' % (ftp_code, version)})

            if 'username' in creds and 'password' in creds:
                success = ftpscan.auth(creds['username'], creds['password'])
            else:
                success = ftpscan.auth()
            if success:
                if 'username' in creds and 'password' in creds:
                    Output.write({'target': ftpscan.url(), 'message': 'Successful connection with credentials %s:%s' % creds})
                else:
                    Output.write({'target': ftpscan.url(), 'message': 'Successful anonymous connection'})

                if 'list' in actions:
                    try:
                        ftp_dir = '/'
                        contents = ""
                        for content in ftpscan.list_content(ftp_dir, recurse=actions['list']['recurse']):
                            if 'size' in content:
                                contents += " "*80+"- %s %s\n" % (content['name'].ljust(30), sizeof_fmt(content['size']))
                            else:
                                contents += " "*80+"- %s\n" % content['name']
                        Output.write({'target': ftpscan.url(), 'message': 'Contents of %s\n%s' % (ftp_dir, contents)})
                    except socket.timeout as e:
                        Output.write({'target': ftpscan.url(), 'message': 'Timeout while listing folder, do you have a firewall enabled ?'})


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


def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, 'Yi', suffix)

