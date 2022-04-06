#!/usr/bin/python3
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.dnsscan.dnsscan import dnsscan_worker

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='DNSScan')
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('--dns', metavar='dns_ip', nargs='?', type=str, help='DNS server to send query to', default=None, dest='dns')
    parser.add_argument('--bruteforce', metavar='file', nargs='?', type=str, help='Bruteforce subdomains', default=None, dest='bruteforce')
    parser.add_argument('--axfr', action='store_true', help='AXFR check', dest='axfr')
    parser.add_argument('--dc', action='store_true', help='Look for a Domain Controler from a domain', dest='dc')
    parser.add_argument('--tcp', action='store_true', help='Make TCP queries', dest='do_tcp')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    parser.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    # Resume
    parser.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    Output.setup()

    Config.load_config()
    DB.start_worker(args.nodb)

    targets = {}
    if args.targets:
        targets['targets'] = args.targets
    if args.target_file:
        targets['target_file'] = args.target_file

    static_inputs = {}

    actions = []
    if args.bruteforce:
        actions.append(('bruteforce', args.bruteforce))
    if args.axfr:
        actions.append(('axfr',))
    if args.dc:
        actions.append(('dc',))

    dnsscan(targets, static_inputs, args.workers, args.dns, args.do_tcp, actions, args.timeout, args.delay, args.resume)

    DB.stop_worker()
    Output.stop()

def dnsscan(input_targets, static_inputs, workers, dns, do_tcp, actions, timeout, delay, resume):

    args = (dns, do_tcp, actions, timeout)

    dispatch_targets(input_targets, static_inputs, dnsscan_worker, args, workers=workers, delay=delay, resume=resume)

if __name__ == '__main__':
    main()
