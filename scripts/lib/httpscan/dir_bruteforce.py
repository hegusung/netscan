import os.path
import copy
from urllib.parse import urlparse
from utils.utils import detect_encoding


def iter_directory_items(dir_file):
    encoding = detect_encoding(dir_file)
    with open(dir_file, encoding=encoding) as wordlist:
        for line in wordlist:
            directory_item = line.split('#')[0].strip()
            if not directory_item or "://" in directory_item:
                continue
            yield directory_item


def dir_file_count(dir_file):
    return sum(1 for _ in iter_directory_items(dir_file))

def dir_bruteforce_generator(target, dir_file, extension_list):
    for dir_item in iter_directory_items(dir_file):
        for extension in extension_list:
            if len(extension) != 0:
                path = os.path.join(target['path'], "%s.%s" % (dir_item, extension))
            else:
                path = os.path.join(target['path'], dir_item)

            t = copy.copy(target)

            url = "%s://%s:%d%s" % (target['method'], target['hostname'], target['port'], path)

            o = urlparse(url)

            method = o.scheme
            netloc = o.netloc
            path = o.path
            params = o.query

            # Check if IPv6
            n_column = netloc.count(':')
            if n_column > 1:
                # IPv6

                if netloc.startswith('['):
                    # [IPv6]:port format

                    hostname = netloc[1:].split(']')[0]
                    port = int(netloc[1:].split(']')[-1][1:])
                else:
                    hostname = netloc
                    port = method_port[method]

            else:
                if n_column == 1:
                    # IP:port or Host:port

                    port = int(netloc.split(':')[-1])
                    hostname = netloc.split(':')[0]
                else:
                    port = method_port[method]
                    hostname = netloc

            res = {}
            if method:
                t['method'] = method
            if not hostname:
                continue
            else:
                t['hostname'] = hostname
            if port:
                t['port'] = port
            if path:
                t['path'] = path
            if params:
                t['params'] = {}
                for param in params.split('&'):
                    key = param.split('=', 1)[0]
                    try:
                        value = param.split('=', 1)[1]
                    except IndexError:
                        value = None
                    t['params'][key] = value

            yield t

