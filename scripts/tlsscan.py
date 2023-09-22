#!/usr/bin/env python3

import argparse
from utils.utils import normalize_path
from utils.process_inputs import str_ports, port_file
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.tlsscan.tlsscan import tlsscan_worker

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='TLSScan')
    target_group = parser.add_argument_group("Targets")
    target_group.add_argument('targets', type=str, nargs='?')
    target_group.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    target_group.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='443', dest='port')
    target_group.add_argument('--port-file', metavar='Port-file', nargs='?', type=port_file, help='Specify a port file', default=None, dest='port_file')

    check_group = parser.add_argument_group("Checks")
    check_group.add_argument("--mozilla-config", action="store", dest="mozilla_config",
            choices=["old", "intermediate", "modern"],
            help="Shortcut to queue various scan commands needed to check the server's TLS configurations against one"
            ' of Mozilla\'s recommended TLS configuration. Set to "intermediate" by default. Use "disable" to disable'
            " this check.",
            default="intermediate"
        )
    
    misc_group = parser.add_argument_group("Misc")
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers', default=10, dest='workers')
    misc_group.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    misc_group.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    # Resume
    parser.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    # DB arguments
    misc_group.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

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

    tlsscan(targets, static_inputs, args.workers, args.mozilla_config, args.timeout, args.delay, args.resume)


    DB.stop_worker()
    Output.stop()


def tlsscan(input_targets, static_inputs, workers, mozilla_config, timeout, delay, resume):
    args = (mozilla_config, timeout)
    dispatch_targets(input_targets, static_inputs, tlsscan_worker, args, workers=workers, delay=delay, resume=resume)


if __name__ == '__main__':
    main()
