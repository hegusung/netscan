import os.path
import impacket
from time import sleep
import socket
import traceback
import struct
import pymongo.errors

from .mongo import Mongo
from .mongo_bruteforce import *

from utils.utils import AuthFailure
from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB

def mongoscan_worker(target, actions, creds, timeout):
    try:
        auth = False
        version_printed = False

        mongo = Mongo(target['hostname'], target['port'], timeout)

        # try anonymous auth
        auth, version = mongo.auth(None, None)

        account = None

        if auth:
            version_printed = True
            Output.write({'target': mongo.url(), 'message': 'Mongodb %s' % version})
            DB.insert_port({
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'mongo',
                'version': 'Mongodb %s' % version,
            })

            Output.vuln({'target': mongo.url(), 'message': 'Authentication success with anonymous credentials'})
            account = 'anonymous'
            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'mongo',
                'url': mongo.url(),
                'name': 'Anonymous connection to service',
                'description': 'Anonymous account can connect to mongodb service: %s' % mongo.url(),
            }
            DB.insert_vulnerability(vuln_info)

        if 'username' in creds and 'password' in creds:
            mongo_auth = Mongo(target['hostname'], target['port'], timeout)
            auth2, version = mongo_auth.auth(creds['username'], creds['password'], database=target['database'])

            if auth2:
                auth = auth2
                if not version_printed:
                    Output.write({'target': mongo.url(), 'message': version})
                    DB.insert_port({
                        'hostname': target['hostname'],
                        'port': target['port'],
                        'protocol': 'tcp',
                        'service': 'mongo',
                        'version': version,
                    })

                Output.success({'target': mongo.url(), 'message': 'Authentication success with username %s and password %s for database \'%s\'' % (creds['username'], creds['password'], target['database'])})
                cred_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'mongo',
                    'url': mongo.url(),
                    'type': 'password',
                    'username': creds['username'],
                    'password': creds['password'],
                }
                DB.insert_credential(cred_info)

                account = creds['username']
                mongo.disconnect()
                mongo = mongo_auth

        if not auth:
            Output.write({'target': mongo.url(), 'message': 'Unknown'})
            DB.insert_port({
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'mongo',
            })

        else:
            if 'list_dbs' in actions:
                databases = mongo.list_databases()
                output = "Databases:\n"
                for db in databases:
                    output += " "*60+"- %s:\n" % db['name']
                    for table in db['collections']:
                        output += " "*60+"\t- %s\n" % table

                        db_info = {
                            'hostname': target['hostname'],
                            'port': target['port'],
                            'url': mongo.url(),
                            'service': 'mongo',
                            'database': db['name'],
                            'table': table,
                        }
                        if account != None:
                            db_info['account'] = account
                        DB.insert_database(db_info)
                Output.highlight({'target': mongo.url(), 'message': output})

        if 'bruteforce' in actions:
            if 'username_file' in actions['bruteforce'] != None:
                Output.highlight({'target': mongo.url(), 'message': 'Starting bruteforce:'})

                username_file = actions['bruteforce']['username_file']
                password_file = actions['bruteforce']['password_file'] if 'password_file' in actions['bruteforce'] else None
                bruteforce_workers = actions['bruteforce']['workers']

                # The generator will provide a username:password_list couple
                gen = bruteforce_generator(target, username_file, password_file)
                gen_size = bruteforce_generator_count(target, username_file, password_file)

                args = (timeout,)
                dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])

    except pymongo.errors.ServerSelectionTimeoutError:
        pass
    except OSError:
        pass
    except ConnectionRefusedError:
        pass
    except Exception as e:
        Output.write({'target': mongo.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        try:
            mongo.disconnect()
        except:
            pass

