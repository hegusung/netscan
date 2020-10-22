#!/usr/bin/python3
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.ftpscan.ftpscan import ftpscan_worker

def main():
    parser = argparse.ArgumentParser(description='FTPScan')
    parser.add_argument('targets', type=str)
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='21', dest='port')
    parser.add_argument('--list', action='store_true', help='List contents if auth success', dest='list')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    args = parser.parse_args()

    static_inputs = {}
    if args.port:
        static_inputs['port'] = args.port

    actions = {}
    if args.list:
        actions['list'] = True

    Output.setup()

    ftpscan(args.targets, static_inputs, args.workers, actions, args.timeout)

    Output.stop()

def ftpscan(input_targets, static_inputs, workers, actions, timeout):

    args = (actions, timeout)

    dispatch_targets(input_targets, static_inputs, ftpscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
