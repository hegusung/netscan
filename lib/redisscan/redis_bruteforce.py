import copy
from .redis import Redis
from utils.output import Output
from utils.utils import AuthFailure
from utils.db import DB

def bruteforce_worker(target, timeout):
    password = target['b_password']

    redis = Redis(target['hostname'], target['port'], timeout)

    success = False
    stop = False
    success, _ = redis.auth(password)
    if success:
        Output.success({'target': redis.url(), 'message': 'Authentication success with password %s' % (password,)})
        cred_info = {
            'hostname': target['hostname'],
            'port': target['port'],
            'service': 'redis',
            'url': redis.url(),
            'type': 'password',
            'username': 'N/A',
            'password': password,
        }
        DB.insert_credential(cred_info)

    try:
        redis.disconnect()
    except:
        pass

def bruteforce_generator(target, password_file):
    password_f = open(password_file)
    for p in password_f:
        p = p.strip()
        if len(p) == 0:
            continue

        t = copy.copy(target)
        t['b_password'] = p

        yield t
    password_f.close()

def bruteforce_generator_count(target, password_file):
    count = 0

    password_f = open(password_file)
    for p in password_f:
        p = p.strip()
        if len(p) == 0:
            continue

        count += 1
    password_f.close()

    return count
