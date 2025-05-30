#!/usr/bin/env python3

import argparse
from utils.utils import normalize_path
from utils.process_inputs import str_ports, port_file
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.jdwpscan.jdwpscan import jdwpscan_worker

from utils.db import DB
from utils.config import Config
from utils.argparse_format import ColoredSelectiveDefaultsHelpFormatter


def main():
    parser = argparse.ArgumentParser(description='JDWPScan - Java Debug Wire Protocol scanner', formatter_class=ColoredSelectiveDefaultsHelpFormatter)
    target_group = parser.add_argument_group("Targets")
    target_group.add_argument('targets', type=str, nargs='?')
    target_group.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    target_group.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', dest='port')
    target_group.add_argument('--port-file', metavar='Port-file', nargs='?', type=port_file, help='Specify a port file', default=None, dest='port_file')

    action_group = parser.add_argument_group("Action")
    action_group.add_argument('--break-on', metavar='JAVA_METHOD', nargs='?', type=str, help='Specify full path to method to break on', default="java.net.ServerSocket.accept", dest='break_on')
    action_group.add_argument("--classes", action="store_true", help="Get classes info")
    action_group.add_argument("--system-info", action="store_true", help="Get system info (requires breakpoint, so might hang)")
    action_group.add_argument('--exec', metavar='COMMAND', nargs='?', type=str, help='Command to execute', default=None, dest='exec')

    misc_group = parser.add_argument_group("Misc")
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers', default=10, dest='workers')
    misc_group.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    misc_group.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')
    # Resume
    misc_group.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')
    # DB arguments
    misc_group.add_argument("--nodb", action="store_true", help="Do not add entries to database")

    args = parser.parse_args()

    Output.setup()
    Config.load_config()
    DB.start_worker(args.nodb)
    DB.save_start()

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

    actions = {}
    if args.classes:
        actions['classes'] = {}
    if args.system_info:
        actions['system_info'] = {'break_on': args.break_on}
    if args.exec:
        actions['exec'] = {'break_on': args.break_on, 'command': args.exec}

    jdwpscan(targets, static_inputs, args.workers, actions, args.timeout, args.delay, args.resume)


    DB.stop_worker()
    Output.stop()


def jdwpscan(input_targets, static_inputs, workers, actions, timeout, delay, resume):
    args = (actions, timeout)
    dispatch_targets(input_targets, static_inputs, jdwpscan_worker, args, workers=workers, delay=delay, resume=resume)


if __name__ == '__main__':
    main()
