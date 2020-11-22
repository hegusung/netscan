import random
import os.path
import string
import re

class AuthFailure(Exception):
    pass

def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, 'Yi', suffix)

def gen_random_string(length=10):
    return ''.join(random.sample(string.ascii_letters, int(length)))

def gen_bruteforce_creds(args, default_creds):
    for arg in args.split(','):
        if arg == 'default':
            for cred in default_creds:
                yield cred
        else:
            if os.path.exists(arg):
                f = open(arg)
                for line in f:
                    line = line.strip()
                    if len(line) != 0:
                        yield line
                f.close()
            else:
                print('Inexistant file: %s' % arg)

ip_regex = re.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
def check_ip(ip):
    if ip_regex.match(ip):
        return True
    else:
        return False


