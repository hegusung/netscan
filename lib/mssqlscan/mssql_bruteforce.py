import copy
from .mssql import MSSQLScan
from utils.output import Output
from utils.utils import AuthFailure

def bruteforce_worker(target, timeout):
    for password in target['b_password_list']:
        domain = target['b_domain']
        username = target['b_username']

        mssqlscan = MSSQLScan(target['hostname'], target['port'], timeout)

        success = mssqlscan.connect()

        if not success:
            Output.write({'target': mssqlscan.url(), 'message': 'Unable to connect to MSSQL server'})
            continue

        if not domain:
            user = username
        else:
            user = '%s\\%s' % (domain, username)

        success = False
        stop = False
        try:
            success, is_admin = mssqlscan.auth(target['b_domain'], target['b_username'], password, None)
            Output.write({'target': mssqlscan.url(), 'message': 'Authentication success with credentials %s and password %s' % (user, password)})

            if is_admin:
                Output.write({'target': mssqlscan.url(), 'message': 'Administrative privileges with account %s' % (user,)})

        except AuthFailure as e:
            pass

        try:
            mssqlscan.disconnect()
        except:
            pass

        if stop:
            break

def bruteforce_generator(target, domain, username_file, password_file, simple_bruteforce=False):
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

        if '\\' in u:
            d = u.split('\\', 1)[0]
            u = u.split('\\', 1)[-1]
        else:
            d = domain

        t = copy.copy(target)
        t['b_domain'] = d
        t['b_username'] = u
        t['b_password_list'] = p

        yield t
    username_f.close()

def bruteforce_generator_count(target, domain, username_file, password_file):
    count = 0

    username_f = open(username_file)
    for u in username_f:
        u = u.strip()
        if len(u) == 0:
            continue

        count += 1
    username_f.close()

    return count
