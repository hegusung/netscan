#!/usr/bin/python3

import argparse
from http_server import run

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP Server')
    parser.add_argument('ip', help='Listening IP', type=str, nargs='?', default='0.0.0.0')
    parser.add_argument('port', help='Listening port', type=int, nargs='?', default=8000)

    args = parser.parse_args()

    # Start the http server
    print('Starting HTTP server at http://%s:%d/' % (args.ip, args.port))
    run(args.ip, args.port)
