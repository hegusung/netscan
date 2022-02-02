#!/usr/bin/python3
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.rtspscan.rtspscan import rtspscan_worker

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='RTSPScan')
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='554', dest='port')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    parser.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    # Actions
    parser.add_argument("--screenshot", action='store_true', help='Take a screenshot')
    # Bruteforce
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
    # Resume
    parser.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    # DB arguments
    parser.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

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

    creds = {}

    actions = {}
    if args.screenshot:
        actions['screenshot'] = {}

    Output.setup()

    rtspscan(targets, static_inputs, args.workers, actions, creds, args.timeout, args.delay, args.resume)


    DB.stop_worker()
    Output.stop()

def rtspscan(input_targets, static_inputs, workers, actions, creds, timeout, delay, resume):

    args = (actions, creds, timeout)

    dispatch_targets(input_targets, static_inputs, rtspscan_worker, args, workers=workers, delay=delay, resume=resume)

if __name__ == '__main__':
    main()
