import os.path
import impacket
from time import sleep
import socket
import traceback
import struct

from .postgresql import PostgreSQL
from .postgresql_bruteforce import *

from utils.utils import AuthFailure
from utils.output import Output
from utils.dispatch import dispatch

def postgrescan_worker(target, actions, creds, timeout):
    try:
        postgresql = PostgreSQL(target['hostname'], target['port'], timeout)

        if not 'username' in creds:
            pass
        elif not 'password' in creds:
            pass
        else:
            username = creds['username']
            password = creds['password']

            success = False

            success, version = postgresql.auth(username, password)

            postgresql_info = {'version': version}
            postgresql_info['target'] = postgresql.url()
            postgresql_info['message_type'] = 'postgresql'
            Output.write(postgresql_info)

            if success:
                Output.write({'target': postgresql.url(), 'message': 'Successful authentication with credentials %s and password %s' % (username, password)})

                if 'list_dbs' in actions:
                    databases = postgresql.list_databases()
                    output = "Databases:\n"
                    for db in databases:
                        output += " "*60+"- %s:\n" % db['name']
                        for table in db['tables']:
                            output += " "*60+"\t- %s\n" % table
                    Output.write({'target': postgresql.url(), 'message': output})
                if 'cmd' in actions:
                    output = "Command result:\n"
                    output += postgresql.execute_cmd(actions['cmd']['command'])

                    Output.write({'target': postgresql.url(), 'message': output})
            else:
                Output.write({'target': postgresql.url(), 'message': 'Authentication failure with credentials %s and password %s' % (username, password)})


        if 'bruteforce' in actions:
            if 'username_file' in actions['bruteforce'] != None:
                Output.write({'target': postgresql.url(), 'message': 'Starting bruteforce:'})

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
        Output.write({'target': postgresql.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        postgresql.disconnect()

