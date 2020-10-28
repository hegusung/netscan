#!/usr/bin/python3
import os
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.rsyncscan.rsyncscan import rsyncscan_worker

def main():
    parser = argparse.ArgumentParser(description='RSyncScan')
    parser.add_argument('targets', type=str)
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='873', dest='port')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    args = parser.parse_args()

    static_inputs = {}
    static_inputs['port'] = args.port

    Output.setup()

    rsyncscan(args.targets, static_inputs, args.workers, args.timeout)

    Output.stop()

def rsyncscan(input_targets, static_inputs, workers, timeout):

    args = (timeout,)

    dispatch_targets(input_targets, static_inputs, rsyncscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
