import os.path
import impacket
from time import sleep
import socket
import traceback
import struct
import psycopg2

from .postgresql import PostgreSQL
from .postgresql_bruteforce import *

from utils.utils import AuthFailure
from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB

def postgrescan_worker(target, actions, creds, timeout):
    try:
        postgresql = PostgreSQL(target['hostname'], target['port'], timeout)
        postgresql_server = False

        username = creds['username'] if 'username' in creds else None
        password = creds['password'] if 'password' in creds else None

        try:
            success, version = postgresql.auth(username, password)

            postgresql_server = True

            postgresql_info = {'version': version}
            postgresql_info['target'] = postgresql.url()
            postgresql_info['message_type'] = 'postgresql'
            Output.write(postgresql_info)
            DB.insert_port({
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'postgresql',
                'version': version,
            })

            if success:
                Output.success({'target': postgresql.url(), 'message': 'Successful authentication with credentials %s and password %s' % (username, password)})
                cred_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'postgresql',
                    'url': postgresql.url(),
                    'type': 'password',
                    'username': username,
                    'password': password,
                }
                DB.insert_credential(cred_info)

                if 'list_dbs' in actions:
                    databases = postgresql.list_databases()
                    output = "Databases:\n"
                    for db in databases:
                        output += " "*60+"- %s:\n" % db['name']
                        for table in db['tables']:
                            output += " "*60+"\t- %s\n" % table
                            db_info = {
                                'hostname': target['hostname'],
                                'port': target['port'],
                                'url': postgresql.url(),
                                'service': 'postgresql',
                                'database': db['name'],
                                'table': '%s/%s' % (table['schema'], table['name']),
                            }
                            db_info['account'] = username
                            DB.insert_database(db_info)

                    Output.highlight({'target': postgresql.url(), 'message': output})
                if 'list_hashes' in actions:
                    hashes = postgresql.list_hashes()
                    output = "Hashes:\n"
                    for account in hashes:
                        output += " "*60+"- %s   %s\n" % (account['user'], account['hash'])

                    Output.highlight({'target': postgresql.url(), 'message': output})

                if 'cmd' in actions:
                    output = "Command result:\n"
                    output += postgresql.execute_cmd(actions['cmd']['command'])

                    Output.highlight({'target': postgresql.url(), 'message': output})
            else:
                if username != None:
                    Output.minor({'target': postgresql.url(), 'message': 'Authentication failure with credentials %s and password %s' % (username, password)})
        except psycopg2.OperationalError as e:
            if "could not connect to server" in str(e) or "timeout expired" in str(e) or "Connection refused" in str(e) or "server closed the connection unexpectedly" in str(e) or "Network is unreachable" in str(e):
                pass
            elif "FATAL: " in str(e):
                postgresql_server = True
                postgresql_info = {'version': 'Unknown'}
                postgresql_info['target'] = postgresql.url()
                postgresql_info['message_type'] = 'postgresql'
                Output.write(postgresql_info)
                DB.insert_port({
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'protocol': 'tcp',
                    'service': 'postgresql',
                })
            elif "fe_sendauth:" in str(e):
                postgresql_server = True
                postgresql_info = {'version': 'Unknown'}
                postgresql_info['target'] = postgresql.url()
                postgresql_info['message_type'] = 'postgresql'
                Output.write(postgresql_info)
                DB.insert_port({
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'protocol': 'tcp',
                    'service': 'postgresql',
                })

            else:
                raise e

        if postgresql_server == True:
            if 'bruteforce' in actions:
                if 'username_file' in actions['bruteforce'] != None:
                    Output.highlight({'target': postgresql.url(), 'message': 'Starting bruteforce:'})

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
        raise e
    finally:
        try:
            postgresql.disconnect()
        except:
            pass

