import os.path
import impacket
from time import sleep
import socket
import traceback
import struct
import mysql.connector

from .mysql import MySQLScan, NotMysql
from .mysql_bruteforce import *

from utils.utils import AuthFailure
from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB

def mysqlscan_worker(target, actions, creds, timeout):
    try:
        mysqlscan = MySQLScan(target['hostname'], target['port'], timeout)

        # We are against a MySQL server

        # Gather info
        version = mysqlscan.get_server_version_unauth()

        mysql_info = {'version': version if version != None else 'Unknown'}
        mysql_info['target'] = mysqlscan.url()
        mysql_info['message_type'] = 'mysql'
        Output.write(mysql_info)
        db_data = {
            'hostname': target['hostname'],
            'port': target['port'],
            'protocol': 'tcp',
            'service': 'mysql',
        }
        if version:
            db_data['version'] = version
        DB.insert_port(db_data)

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
                Output.success({'target': mysqlscan.url(), 'message': 'Successful authentication with credentials %s and password %s' % (username, password)})
                cred_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'mysql',
                    'url': mysqlscan.url(),
                    'type': 'password',
                    'username': username,
                    'password': password,
                }
                DB.insert_credential(cred_info)

            except AuthFailure as e:
                Output.minor({'target': mysqlscan.url(), 'message': 'Authentication failure with credentials %s and password %s: %s' % (username, password, str(e))})

            if success:
                if 'list_dbs' in actions:
                    databases = mysqlscan.list_databases()
                    output = "Databases:\n"
                    for db in databases:
                        output += " "*60+"- %s:\n" % db['name']
                        for table in db['tables']:
                            output += " "*60+"\t- %s\n" % table

                            db_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'url': mysqlscan.url(),
                                'service': 'mysql',
                                'database': db['name'],
                                'table': table,
                            }
                            db_info['account'] = username
                            DB.insert_database(db_info)

                    Output.highlight({'target': mysqlscan.url(), 'message': output})
                if 'list_hashes' in actions:
                    hashes = mysqlscan.list_hashes()
                    output = "Hashes:\n"
                    for account in hashes:
                        user = "%s%%%s" % (account['username'], account['host'])
                        output += " "*60+"- %s   %s\n" % (user, account['hash'])
                    Output.highlight({'target': mysqlscan.url(), 'message': output})
                if 'sql' in actions:
                    output = "Query result:\n"
                    result = mysqlscan.execute_sql(actions['sql']['query'])
                    for item in result:
                        output += "- %s\n" % (item,)

                    Output.highlight({'target': mysqlscan.url(), 'message': output})


        if 'bruteforce' in actions:
            if 'username_file' in actions['bruteforce'] != None:
                Output.highlight({'target': mysqlscan.url(), 'message': 'Starting bruteforce:'})

                username_file = actions['bruteforce']['username_file']
                password_file = actions['bruteforce']['password_file'] if 'password_file' in actions['bruteforce'] else None
                bruteforce_workers = actions['bruteforce']['workers']

                # The generator will provide a username:password_list couple
                gen = bruteforce_generator(target, username_file, password_file)
                gen_size = bruteforce_generator_count(target, username_file, password_file)

                args = (timeout,)
                dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])

    except mysql.connector.errors.DatabaseError as e:
        Output.write({'target': mysqlscan.url(), 'message': str(e)})
    except NotMysql:
        pass
    except OSError:
        pass
    except ConnectionRefusedError:
        pass
    except Exception as e:
        Output.write({'target': mysqlscan.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        mysqlscan.disconnect()

