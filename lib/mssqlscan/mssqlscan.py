import os.path
import impacket
from time import sleep
import socket
import traceback
import struct

from .mssql import MSSQLScan
from .mssql_bruteforce import *

from utils.utils import AuthFailure
from utils.output import Output
from utils.dispatch import dispatch

def mssqlscan_worker(target, actions, creds, timeout):
    try:
        mssqlscan = MSSQLScan(target['hostname'], target['port'], timeout)

        if mssqlscan.connect():
            # We are against a MSSQL server

            # Gather info
            mssql_info = mssqlscan.get_server_info()
            mssql_info['target'] = mssqlscan.url()
            mssql_info['message_type'] = 'mssql'
            Output.write(mssql_info)

            mssqlscan.disconnect()

            if not 'username' in creds:
                pass
            elif not 'password' in creds and not 'hash' in creds:
                pass
            else:
                username = creds['username']
                domain = creds['domain'] if 'domain' in creds else None
                password = creds['password'] if 'password' in creds else None
                ntlm_hash = creds['hash'] if 'hash' in creds else None

                success = False
                is_admin = False

                if not domain:
                    user = username
                else:
                    user = '%s\\%s' % (domain, username)

                mssqlscan.connect()

                try:
                    success, is_admin = mssqlscan.auth(domain, username, password, ntlm_hash)
                    if password:
                        Output.write({'target': mssqlscan.url(), 'message': 'Successful authentication with credentials %s and password %s' % (user, password)})
                    else:
                        Output.write({'target': mssqlscan.url(), 'message': 'Successful authentication with credentials %s and hash %s' % (user, ntlm_hash)})
                except AuthFailure as e:
                    if password:
                        Output.write({'target': mssqlscan.url(), 'message': 'Authentication failure with credentials %s and password %s: %s' % (user, password, str(e))})
                    else:
                        Output.write({'target': mssqlscan.url(), 'message': 'Authentication failure with credentials %s and hash %s: %s' % (user, ntlm_hash, str(e))})

                if is_admin:
                    Output.write({'target': mssqlscan.url(), 'message': 'Administrative privileges with account %s' % user})

                if success:
                    if 'list_dbs' in actions:
                        databases = mssqlscan.list_databases()
                        output = "Databases:\n"
                        for db in databases:
                            output += " "*60+"- %s:\n" % db['name']
                            for table in db['tables']:
                                output += " "*60+"\t- %s\n" % table
                        Output.write({'target': mssqlscan.url(), 'message': output})
                    if 'list_admins' in actions:
                        admins = mssqlscan.list_admins()
                        output = "Admins:\n"
                        for admin in admins:
                            output += " "*60+"- %s\n" % admin
                        Output.write({'target': mssqlscan.url(), 'message': output})
                    if 'list_hashes' in actions:
                        hashes = mssqlscan.list_hashes()
                        output = "Hashes:\n"
                        for account in hashes:
                            output += " "*60+"- %s   %s\n" % (account['name'].ljust(30), account['password_hash'].decode())
                        Output.write({'target': mssqlscan.url(), 'message': output})
                    if 'sql' in actions:
                        output = "Query result:\n"
                        result = mssqlscan.execute_sql(actions['sql']['query'])
                        for item in result:
                            output += "- %s\n" % (item,)

                        Output.write({'target': mssqlscan.url(), 'message': output})
                    if 'cmd' in actions:
                        output = "Command output:\n"
                        result = mssqlscan.execute_cmd(actions['cmd']['command'])
                        output += result
                        Output.write({'target': mssqlscan.url(), 'message': output})


            if 'bruteforce' in actions:
                if 'username_file' in actions['bruteforce'] != None:
                    Output.write({'target': mssqlscan.url(), 'message': 'Starting bruteforce:'})

                    if 'domain' in creds:
                        domain = creds['domain']
                    else:
                        domain = None
                    username_file = actions['bruteforce']['username_file']
                    password_file = actions['bruteforce']['password_file'] if 'password_file' in actions['bruteforce'] else None
                    bruteforce_workers = actions['bruteforce']['workers']

                    # The generator will provide a username:password_list couple
                    gen = bruteforce_generator(target, domain, username_file, password_file)
                    gen_size = bruteforce_generator_count(target, domain, username_file, password_file)

                    args = (timeout,)
                    dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])

    except OSError:
        pass
    except ConnectionRefusedError:
        pass
    except Exception as e:
        Output.write({'target': mssqlscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        mssqlscan.disconnect()

