import copy
from .mongo import Mongo
from utils.output import Output
from utils.utils import AuthFailure
from utils.db import DB

def bruteforce_worker(target, timeout):
    for password in target['b_password_list']:
        username = target['b_username']

        mongo = Mongo(target['hostname'], target['port'], timeout)

        success = False
        stop = False
        success, _ = mongo.auth(username, password, database=target['database'])
        if success:
            Output.success({'target': mongo.url(), 'message': 'Authentication success with credentials %s and password %s and database \'%s\'' % (username, password, target['database'])})
            cred_info = {
                'hostname': target['hostname'],
                'port': target['port'],
                'service': 'mongo',
                'url': mongo.url(),
                'type': 'password',
                'username': username,
                'password': password,
            }
            DB.insert_credential(cred_info)

            stop = True

        try:
            mongo.disconnect()
        except:
            pass

        if stop:
            break

def bruteforce_generator(target, username_file, password_file, simple_bruteforce=False):
    password_list = []
    if password_file != None:
        password_f = open(password_file)
        for f in password_f:
            f = f.strip()
            password_list.append(f)
        password_f.close()

    username_f = open(username_file)
    for u in username_f:
        u = u.strip()
        if len(u) == 0:
            continue

        if not simple_bruteforce:
            if ':' in u:
                p = [u.split(':', 1)[-1]]
                u = u.split(':', 1)[0]
            else:
                p = password_list
        else:
            if ':' in u:
                u = u.split(':', 1)[0]
            p = [u]

        t = copy.copy(target)
        t['b_username'] = u
        t['b_password_list'] = p

        yield t
    username_f.close()

def bruteforce_generator_count(target, username_file, password_file):
    count = 0

    username_f = open(username_file)
    for u in username_f:
        u = u.strip()
        if len(u) == 0:
            continue

        count += 1
    username_f.close()

    return count
