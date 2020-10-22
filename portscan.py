#!/usr/bin/python3
import os
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.portscan.portscan import portscan_worker, top_ports

def main():
    parser = argparse.ArgumentParser(description='PortScan')
    parser.add_argument('targets', type=str)
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default=None, dest='port')
    parser.add_argument('--top-ports', metavar='top-N', nargs='?', type=top_ports, help='top n ports', default=None, dest='top_ports')
    parser.add_argument('-sV', action='store_true', help='Service scan (nmap)', dest='service_scan')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    args = parser.parse_args()

    static_inputs = {}
    static_inputs['port'] = []
    if args.port:
        static_inputs['port'] += args.port
    if args.top_ports:
        static_inputs['port'] += args.top_ports
    static_inputs['port'] = list(set(static_inputs['port']))

    if len(static_inputs['port']) == 0:
        print('Please specify some ports')
        return

    Output.setup()

    portscan(args.targets, static_inputs, args.workers, args.service_scan, args.timeout)

    Output.stop()

def portscan(input_targets, static_inputs, workers, service_scan, timeout):

    args = (service_scan, timeout)

    dispatch_targets(input_targets, static_inputs, portscan_worker, args, workers=workers)

    # Nmap can break the terminal, so fix it
    os.system("stty echo")

if __name__ == '__main__':
    main()
