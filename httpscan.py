#!/usr/bin/python3
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch
from utils.output import Output
from lib.httpscan.httpscan import httpscan_worker

def main():
    parser = argparse.ArgumentParser(description='HTTPScan')
    parser.add_argument('targets', type=str)
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='80,443', dest='port')
    parser.add_argument('--method', metavar='methods', type=str_comma, nargs='?', help='methods to connect', default='http,https', dest='method')
    parser.add_argument('--path', metavar='path', nargs='?', type=str_comma, help='HTTP path', default='/', dest='path')
    parser.add_argument('--useragent', metavar='useragent', nargs='?', type=str, help='User agent', default='Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0', dest='useragent')
    parser.add_argument('--dir-bruteforce', metavar='file', nargs='?', type=str, help='Bruteforce path', default=None, dest='dir_bruteforce')
    parser.add_argument('--proxy', metavar='http://ip:port', nargs='?', type=str, help='Proxy', default=None, dest='proxy')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    args = parser.parse_args()

    static_inputs = {}
    if args.port:
        static_inputs['port'] = args.port
    if args.method:
        static_inputs['method'] = args.method
    if args.path:
        static_inputs['path'] = args.path

    Output.setup()

    httpscan(args.targets, static_inputs, args.workers, args.useragent, args.proxy, args.dir_bruteforce, args.timeout)

    Output.stop()

def httpscan(input_targets, static_inputs, workers, useragent, proxy, dir_bruteforce, timeout):

    args = (useragent, proxy, dir_bruteforce, timeout)

    dispatch(input_targets, static_inputs, httpscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
