import copy
import time
from .smb import SMBScan
from utils.output import Output
from utils.utils import AuthFailure
from utils.db import DB

def bruteforce_worker(target, bruteforce_delay, timeout):
    for password in target['b_password_list']:
        time.sleep(bruteforce_delay)

        domain = target['b_domain']
        username = target['b_username']

        smbscan = SMBScan(target['hostname'], target['port'], timeout)

        success = smbscan.connect()

        if not success:
            Output.write({'target': smbscan.url(), 'message': 'Unable to connect to SMB server'})
            continue

        success = False
        stop = False
        try:
            success, is_admin = smbscan.auth(target['b_domain'], target['b_username'], password)
            Output.success({'target': smbscan.url(), 'message': 'Authentication success with credentials %s\\%s and password %s' % (domain, username, password)})
            if domain in [None, 'WORKGROUP']:
                # local account
                cred_info = {
                    'hostname': target['hostname'],
                    'port': target['port'],
                    'service': 'smb',
                    'url': smbscan.url(),
                    'type': 'password',
                    'username': username,
                    'password': password,
                }
                DB.insert_credential(cred_info)

            else:
                # domain account 
                cred_info = {
                    'domain': domain,
                    'username': username,
                    'type': 'password',
                    'password': password,
                }
                DB.insert_domain_credential(cred_info)

            if is_admin:
                Output.major({'target': smbscan.url(), 'message': 'Administrative privileges with credentials %s\\%s' % (domain, username)})

            stop = True

        except AuthFailure as e:
            if str(e) in ["STATUS_ACCOUNT_LOCKED_OUT"]:
                    Output.write({'target': smbscan.url(), 'message': 'Account locked out: %s\\%s' % (domain, username)})
                    stop = True
            elif str(e) in ["STATUS_LOGON_FAILURE"]:
                #Output.write({'target': smbscan.url(), 'message': 'Authentication failure with credentials %s\\%s and password %s: %s' % (domain, username, password, str(e))})
                pass
            else:
                Output.write({'target': smbscan.url(), 'message': 'Authentication failure with credentials %s\\%s and password %s: %s' % (domain, username, password, str(e))})

        try:
            smbscan.disconnect()
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
