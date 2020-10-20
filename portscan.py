#!/usr/bin/python3
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch
from utils.output import Output
from lib.portscan.portscan import portscan_worker

def main():
    parser = argparse.ArgumentParser(description='PortScan')
    parser.add_argument('targets', type=str)
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='80,443', dest='port')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    args = parser.parse_args()

    static_inputs = {}
    if args.port:
        static_inputs['port'] = args.port

    Output.setup()

    portscan(args.targets, static_inputs, args.workers, args.timeout)

    Output.stop()

def portscan(input_targets, static_inputs, workers, timeout):

    args = (timeout,)

    dispatch(input_targets, static_inputs, portscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
