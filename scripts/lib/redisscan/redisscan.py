import os.path
import impacket
from time import sleep
import socket
import traceback
import struct
import redis as redislib

from .redis import Redis
from .redis_bruteforce import *

from utils.utils import AuthFailure
from utils.output import Output
from utils.dispatch import dispatch
from utils.db import DB

def redisscan_worker(target, actions, creds, timeout):
    try:
        auth = False
        version_printed = False

        redis = Redis(target['hostname'], target['port'], timeout)

        # try anonymous auth
        auth, version = redis.auth(None)

        if auth:
            version_printed = True
            Output.write({'target': redis.url(), 'message': version})
            DB.insert_port({
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'redis',
                'version': version,
            })

            Output.vuln({'target': redis.url(), 'message': 'Authentication success with anonymous credentials'})
            vuln_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'redis',
                'url': redis.url(),
                'name': 'Anonymous connection to service',
                'description': 'Anonymous account can connect to redis service: %s' % redis.url(),
            }
            DB.insert_vulnerability(vuln_info)

        if 'password' in creds:
            redis_auth = Redis(target['hostname'], target['port'], timeout)
            auth2, version2 = redis_auth.auth(creds['password'])

            if auth2:
                auth = auth2
                version = version2
                if not version_printed:
                    Output.write({'target': redis.url(), 'message': version})
                Output.success({'target': redis.url(), 'message': 'Authentication success with password %s' % (creds['password'],)})
                cred_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'redis',
                    'url': redis.url(),
                    'type': 'password',
                    'username': 'N/A',
                    'password': creds['password'],
                }
                DB.insert_credential(cred_info)

                redis.disconnect()
                redis = redis_auth

        if version:
            # check if vulnerable to CVE-2015-4335
            version_tuple = tuple([int(i) for i in version.split(".")])

            if version_tuple < (2, 8, 21) or version_tuple[0] == 3 and version_tuple < (3, 0, 2):
                Output.vuln({'target': redis.url(), 'message': "RCE on Redis (CVE-2015-4335)"})

        if not auth:
            Output.write({'target': redis.url(), 'message': 'Unknown'})
            DB.insert_port({
                'hostname': target['hostname'],
                'port': target['port'],
                'protocol': 'tcp',
                'service': 'redis',
            })

        else:
            """
            if 'list_dbs' in actions:
                databases = redis.list_databases()
                output = "Databases:\n"
                for db in databases:
                    output += " "*60+"- %s:\n" % db['name']
                    for table in db['collections']:
                        output += " "*60+"\t- %s\n" % table
                Output.write({'target': redis.url(), 'message': output})
            """

        if 'bruteforce' in actions:
            if 'password_file' in actions['bruteforce'] != None:
                Output.write({'target': redis.url(), 'message': 'Starting bruteforce:'})

                password_file = actions['bruteforce']['password_file']
                bruteforce_workers = actions['bruteforce']['workers']

                # The generator will provide a username:password_list couple
                gen = bruteforce_generator(target, password_file)
                gen_size = bruteforce_generator_count(target, password_file)

                args = (timeout,)
                dispatch(gen, gen_size, bruteforce_worker, args, workers=bruteforce_workers, process=False, pg_name=target['hostname'])

    except OSError:
        pass
    except ConnectionRefusedError:
        pass
    except redislib.exceptions.ConnectionError:
        pass
    except redislib.exceptions.TimeoutError:
        pass
    except Exception as e:
        Output.write({'target': redis.url(), 'message': '%s: %s\n%s' % (type(e), e, traceback.format_exc())})
    finally:
        redis.disconnect()

