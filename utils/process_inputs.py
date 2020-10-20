import re
import copy
from urllib.parse import urlparse
from netaddr import *

method_port = {
    "http": 80,
    "https": 443,
    "mssql": 3306,
    "smb": 445,
}

ipv4_regex = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[012]|[12][0-9]|[1-9]))?$')

"""
Used by argparse arguments
"""

def str_comma(input_str):
    return list(set(input_str.split(',')))

def str_ports(input_str):
    ports = []
    for input_ports in input_str.split(','):
        if '-' in input_ports:
            ports += list(range(int(input_ports.split('-')[0]), int(input_ports.split('-')[-1])+1))
        else:
            ports.append(int(input_ports))

    return list(set(ports))

"""
Creates a generator with inputs
"""
def process_inputs(targets_str, static_inputs):
    static_keys = static_inputs.keys()

    for target in process_targets(targets_str):
        for key in static_keys:
            if not key in target:
                target[key] = static_inputs[key]

        # Now yield for each item in each list
        for t in iter_target_rec(target, list(target.keys()), 0):
            yield t

def count_process_inputs(targets_str, static_inputs):
    count = 0
    static_keys = static_inputs.keys()

    for target in process_targets(targets_str):
        for key in static_keys:
            if not key in target:
                target[key] = static_inputs[key]

        target_count = 1
        for key in target:
            if type(target[key]) == list:
                target_count = target_count*len(target[key])
            elif type(target[key]) == IPNetwork:
                target_count = target_count*target[key].size

        count += target_count

    return count

def iter_target_rec(target, keys, key_id):
    if key_id >= len(keys):
        yield target
    else:
        if type(target[keys[key_id]]) not in [list, IPNetwork]:
            for t in iter_target_rec(target, keys, key_id+1):
                yield t
        else:
            t = copy.copy(target)
            for i in target[keys[key_id]]:
                if type(i) == IPAddress:
                    t[keys[key_id]] = str(i)
                else:
                    t[keys[key_id]] = i
                for t2 in iter_target_rec(t, keys, key_id+1):
                    yield t2


"""
Output: dict(method, hostname, port, path)
"""
def process_targets(targets_str):

    for target_str in targets_str.split(','):
        if "://" in target_str:
            # If target_str is a url form: method://hostname:port/path

            o = urlparse(target_str)

            method = o.scheme
            netloc = o.netloc
            path = o.path

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
                res['method'] = method
            if not hostname:
                continue
            else:
                res['hostname'] = hostname
            if port:
                res['port'] = port
            if path:
                res['path'] = path

            yield res
        else:
            # If target_str is in ip:port or ip format, ip can be a range
            
            method = None
            path = None

            """
            Possible formats:
                    - IP:Port
                    - IP
                    - IPv6
                    - [IPv6]:Port
                    - Hostname
                    - Hostname:Port
            """

            # Check if IPv6
            n_column = target_str.count(':')

            if n_column > 1:
                # IPv6

                if target_str.startswith('['):
                    # [IPv6]:port format

                    ip_range = target_str[1:].split(']')[0]
                    port = int(target_str[1:].split(']')[-1][1:])
                else:
                    ip_range = target_str
                    port = None

                ip_range = IPNetwork(ip_range)
                res = {
                    'hostname': ip_range
                }
                if port:
                    res['port'] = port

                yield res

            else:
                if n_column == 1:
                    # IP:port or Host:port

                    port = int(target_str.split(':')[-1])
                    target_str = target_str.split(':')[0]
                else:
                    port = None

                if ipv4_regex.match(target_str) != None:
                    ip_range = IPNetwork(target_str)

                    res = {
                            'hostname': ip_range
                    }
                    if port:
                        res['port'] = port

                    yield res

                else:
                    res = {
                        'hostname': target_str
                    }
                    if port:
                        res['port'] = port

                    yield res
                   
