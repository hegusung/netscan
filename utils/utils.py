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

def detect_encoding(file, encodings=['utf8', 'iso-8859-1', 'utf16']):
    chunk_size = 1000
    try:
        f = open(file, encoding=encodings[0])
        while True:
            data = f.read(chunk_size)
            if not data:
                break
    except UnicodeDecodeError:
        try:
            f.close()
        except:
            pass

        if len(encodings) > 1:
            return detect_encoding(file, encodings=encodings[1:])
        else:
            raise Exception('detect_encoding: Unable to detect encoding for file: %s' % f)
    f.close()

    return encodings[0]

