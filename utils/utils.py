import random
import string

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


