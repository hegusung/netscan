#!/usr/bin/python3
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.dnsscan.dnsscan import dnsscan_worker

def main():
    parser = argparse.ArgumentParser(description='DNSScan')
    parser.add_argument('targets', type=str)
    parser.add_argument('--dns', metavar='dns_ip', nargs='?', type=str, help='DNS server to send query to', default=None, dest='dns')
    parser.add_argument('--bruteforce', metavar='file', nargs='?', type=str, help='Bruteforce subdomains', default=None, dest='bruteforce')
    parser.add_argument('--axfr', action='store_true', help='AXFR check', dest='axfr')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    args = parser.parse_args()

    static_inputs = {}

    Output.setup()

    actions = []
    if args.bruteforce:
        actions.append(('bruteforce', args.bruteforce))
    if args.axfr:
        actions.append(('axfr',))

    dnsscan(args.targets, static_inputs, args.workers, args.dns, actions, args.timeout)

    Output.stop()

def dnsscan(input_targets, static_inputs, workers, dns, actions, timeout):

    args = (dns, actions, timeout)

    dispatch_targets(input_targets, static_inputs, dnsscan_worker, args, workers=workers)

if __name__ == '__main__':
    main()
