#!/usr/bin/python3
import argparse
import sys

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.httpscan.httpscan import httpscan_worker, http_modules

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='HTTPScan')
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='80,443', dest='port')
    parser.add_argument('--method', metavar='methods', type=str_comma, nargs='?', help='methods to connect', default='http,https', dest='method')
    parser.add_argument('--path', metavar='path', nargs='?', type=str_comma, help='HTTP path', default='/', dest='path')
    parser.add_argument('--useragent', metavar='useragent', nargs='?', type=str, help='User agent', default='Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0', dest='useragent')
    parser.add_argument('--dir-bruteforce', metavar='file', nargs='?', type=str, help='Bruteforce path', default=None, dest='dir_bruteforce')
    parser.add_argument('--http-auth', metavar='timeout', nargs='?', type=str, help='401 authentication, format username:password', default=None, dest='http_auth')
    parser.add_argument('-x', metavar='extentions', nargs='?', type=str, help='Bruteforce file extensions', default='', dest='extensions')
    parser.add_argument('-W', metavar='number worker', nargs='?', type=int, help='Number of concurent workers for the directory bruteforce', default=5, dest='dir_bruteforce_workers')
    parser.add_argument('--proxy', metavar='http://ip:port', nargs='?', type=str, help='Proxy', default=None, dest='proxy')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Modules
    parser.add_argument("--list-modules", action="store_true", help="List available modules", dest='list_modules')
    parser.add_argument('-m', metavar='modules', nargs='?', type=str, help='Launch modules', default=None, dest='modules')
    # Module arguments
    parser.add_argument('--exec', metavar='command', nargs='?', type=str, help='Execute command if RCE from a module', default=None, dest='exec')
    parser.add_argument('--bruteforce', metavar='file', nargs='?', type=str, help='Enable bruteforce, file name is optional', default=None, const='default', dest='bruteforce')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    if args.list_modules:
        print('Available modules:')
        for module in http_modules.list_modules():
            print('- %s   %s' % (module['name'].ljust(15), module['description']))
        sys.exit()

    Config.load_config()
    DB.start_worker(args.nodb)

    targets = {}
    if args.targets:
        targets['targets'] = args.targets
    if args.target_file:
        targets['target_file'] = args.target_file

    static_inputs = {}
    if args.port:
        static_inputs['port'] = args.port
    if args.method:
        static_inputs['method'] = args.method
    if args.path:
        static_inputs['path'] = args.path

    actions = {}
    if args.modules:
        module_args = {
            'exec': args.exec,
            'bruteforce': args.bruteforce,
        }
        actions['modules'] = {'modules': args.modules, 'args': module_args}

    Output.setup()
    httpscan(targets, static_inputs, args.workers, actions, args.useragent, args.http_auth, args.proxy, args.dir_bruteforce, args.extensions, args.dir_bruteforce_workers, args.timeout)

    DB.stop_worker()
    Output.stop()

def httpscan(input_targets, static_inputs, workers, actions, useragent, http_auth, proxy, dir_bruteforce, extensions, dir_bruteforce_workers, timeout):

    args = (actions, useragent, http_auth, proxy, dir_bruteforce, extensions, dir_bruteforce_workers, timeout)

    dispatch_targets(input_targets, static_inputs, httpscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
