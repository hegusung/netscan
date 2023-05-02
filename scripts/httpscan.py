#!/usr/bin/env python3

import argparse
import sys
from utils.utils import normalize_path
from utils.process_inputs import str_comma, str_ports, port_file
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
    parser.add_argument('--port-file', metavar='Port-file', nargs='?', type=port_file, help='Specify a port file', default=None, dest='port_file')
    parser.add_argument('--method', metavar='methods', type=str_comma, nargs='?', help='methods to connect', default='http,https', dest='method')
    parser.add_argument('--path', metavar='path', nargs='?', type=str_comma, help='HTTP path', default='/', dest='path')
    parser.add_argument('--useragent', metavar='useragent', nargs='?', type=str, help='User agent', default='Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0', dest='useragent')
    parser.add_argument('--dir-bruteforce', metavar='file', nargs='?', type=str, help='Bruteforce path', default=None, dest='dir_bruteforce')
    parser.add_argument('--http-auth', metavar='username:password', nargs='?', type=str, help='401 authentication, format username:password', default=None, dest='http_auth')
    parser.add_argument('--cookies', metavar='key=value', nargs='?', type=str, help='Comma-separated list of cookies KEY=VALUE', default=None, dest='cookies')
    parser.add_argument('--headers', metavar='header', nargs='?', type=str, help='Comma-separated list of headers KEY=VALUE', default=None, dest='headers')
    parser.add_argument('-x', metavar='extensions', nargs='?', type=str, help='Bruteforce file extensions', default='', dest='extensions')
    parser.add_argument('-W', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers for the directory bruteforce', default=5, dest='dir_bruteforce_workers')
    parser.add_argument('--proxy', metavar='http://ip:port', nargs='?', type=str, help='Proxy', default=None, dest='proxy')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    parser.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    
    # Modules
    parser.add_argument("--list-modules", action="store_true", help="List available modules", dest='list_modules')
    parser.add_argument('-m', metavar='modules', nargs='*', type=str, help='Launch modules ("-m all" to execute all modules)', default=None, dest='modules')
    
    # Module arguments
    parser.add_argument('--exec', metavar='command', nargs='?', type=str, help='Execute command if RCE from a module', default=None, dest='exec')
    parser.add_argument('--bruteforce', metavar='file', nargs='?', type=str, help='Enable bruteforce, file name is optional', default=None, const='default', dest='bruteforce')
    
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers', default=10, dest='workers')
    
    # Resume
    parser.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    if args.list_modules:
        print('Available modules:')
        for module in http_modules.list_modules():
            print('- %s   %s' % (module['name'].ljust(15), module['description']))
        sys.exit()

    Output.setup()
    Config.load_config()
    DB.start_worker(args.nodb)

    targets = {}
    if args.targets:
        targets['targets'] = args.targets
    if args.target_file:
        targets['target_file'] = normalize_path(args.target_file)

    static_inputs = {}
    if args.port:
        static_inputs['port'] = args.port
    if args.port_file:
        static_inputs['port'] += normalize_path(args.port_file)
    if args.method:
        static_inputs['method'] = args.method
    if args.path:
        static_inputs['path'] = args.path

    actions = {}
    if args.modules:
        module_args = {
            'exec': args.exec,
            'bruteforce': args.bruteforce,
            'args': args.modules[1:],
        }
        actions['modules'] = {'modules': args.modules[0], 'args': module_args}

    # Parse cookies
    cookie_dict = {}
    if args.cookies:
        for c in args.cookies.split(','):
            if not '=' in c:
                continue

            key = c.split('=', 1)[0]
            value = c.split('=', 1)[1]

            cookie_dict[key] = value

    # Parse headers
    header_dict = {}
    if args.headers:
        for h in args.headers.split(','):
            if '=' in h:
                key = h.split('=', 1)[0].strip()
                value = h.split('=', 1)[1].strip()
            elif ': ' in h:
                key = h.split(':', 1)[0].strip()
                value = h.split(':', 1)[1].strip()
            else:
                continue

            header_dict[key] = value

    httpscan(targets, static_inputs, args.workers, actions, args.useragent, header_dict, args.http_auth, cookie_dict, args.proxy, normalize_path(args.dir_bruteforce), args.extensions, args.dir_bruteforce_workers, args.timeout, args.delay, args.resume)

    DB.stop_worker()
    Output.stop()


def httpscan(input_targets, static_inputs, workers, actions, useragent, header_dict, http_auth, cookie_dict, proxy, dir_bruteforce, extensions, dir_bruteforce_workers, timeout, delay, resume):
    args = (actions, useragent, header_dict, http_auth, cookie_dict, proxy, dir_bruteforce, extensions, dir_bruteforce_workers, timeout)
    dispatch_targets(input_targets, static_inputs, httpscan_worker, args, workers=workers, delay=delay, resume=resume)


if __name__ == '__main__':
    main()
