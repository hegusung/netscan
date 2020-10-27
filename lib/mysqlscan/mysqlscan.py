import os.path
import impacket
from time import sleep
import socket
import traceback
import struct

from .mysql import MySQLScan
from .mysql_bruteforce import *

from utils.utils import AuthFailure
from utils.output import Output
from utils.dispatch import dispatch

def mysqlscan_worker(target, actions, creds, timeout):
    try:
        mysqlscan = MySQLScan(target['hostname'], target['port'], timeout)

        # We are against a MySQL server

        # Gather info
        version = mysqlscan.get_server_version_unauth()
        if version == None:
            return

        mysql_info = {'version': version}
        mysql_info['target'] = mysqlscan.url()
        mysql_info['message_type'] = 'mysql'
        Output.write(mysql_info)

        if not 'username' in creds:
            pass
        elif not 'password' in creds:
            pass
        else:
            username = creds['username']
            password = creds['password']

            success = False

            try:
                success, version = mysqlscan.auth(username, password)
                Output.write({'target': mysqlscan.url(), 'message': 'Successful authentication with credentials %s and password %s' % (username, password)})
            except AuthFailure as e:
                Output.write({'target': mysqlscan.url(), 'message': 'Authentication failure with credentials %s and password %s: %s' % (username, password, str(e))})

            if success:
                if 'list_dbs' in actions:
                    databases = mysqlscan.list_databases()
                    output = "Databases:\n"
                    for db in databases:
                        output += " "*60+"- %s:\n" % db['name']
                        for table in db['tables']:
                            output += " "*60+"\t- %s\n" % table
                    Output.write({'target': mysqlscan.url(), 'message': output})
                if 'list_hashes' in actions:
                    hashes = mysqlscan.list_hashes()
                    output = "Hashes:\n"
                    for account in hashes:
                        user = "%s%%%s" % (account['username'], account['host'])
                        output += " "*60+"- %s   %s\n" % (user, account['hash'])
                    Output.write({'target': mysqlscan.url(), 'message': output})
                if 'sql' in actions:
                    output = "Query result:\n"
                    result = mysqlscan.execute_sql(actions['sql']['query'])
                    for item in result:
                        output += "- %s\n" % (item,)

                    Output.write({'target': mysqlscan.url(), 'message': output})


        if 'bruteforce' in actions:
            if 'username_file' in actions['bruteforce'] != None:
                Output.write({'target': mysqlscan.url(), 'message': 'Starting bruteforce:'})

                username_file = actions['bruteforce']['username_file']
                password_file = actions['bruteforce']['password_file'] if 'password_file' in actions['bruteforce'] else None
                bruteforce_workers = actions['bruteforce']['workers']

                # The generator will provide a username:password_list couple
                gen = bruteforce_generator(target, username_file, password_file)
                gen_size = bruteforce_generator_count(target, username_file, password_file)

                args = (timeout,)
                dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])

    except OSError:
        pass
    except ConnectionRefusedError:
        pass
    except Exception as e:
        Output.write({'target': mysqlscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        mysqlscan.disconnect()

