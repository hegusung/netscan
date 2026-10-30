#!/usr/bin/env python3

import os
import argparse
from utils.utils import normalize_path
from utils.process_inputs import str_comma, str_ports, port_file
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.mcpscan.mcpscan import mcpscan_worker
from utils.db import DB
from utils.config import Config
from utils.argparse_format import ColoredSelectiveDefaultsHelpFormatter


def main():
    parser = argparse.ArgumentParser(description='MCPScan', formatter_class=ColoredSelectiveDefaultsHelpFormatter)
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument('targets', type=str, nargs='?')
    target_group.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    target_group.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default='3000,8000,8080', dest='port')
    target_group.add_argument('--method', metavar='methods', type=str_comma, nargs='?', help='methods to connect', default='http,https', dest='method')
    target_group.add_argument('--path', metavar='path', nargs='?', type=str_comma, help='HTTP path', default='/mcp', dest='path')
    target_group.add_argument("--resume", metavar='resume_number', type=int, nargs='?', default=0, help='resume scan from a specific value', dest='resume')


    perf_group = parser.add_argument_group('Performance & Timing')
    perf_group.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurrent workers', default=1, dest='workers')
    perf_group.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    perf_group.add_argument('--delay', metavar='seconds', nargs='?', type=int, help='Add a delay between each connections', default=0, dest='delay')

    action_group = parser.add_argument_group('Actions')
    action_group.add_argument("--tools", action="store_true", help="List tools")
    action_group.add_argument("--resources", action="store_true", help="List resources")
 
    infra_group = parser.add_argument_group('Proxy & Infrastructure')
    infra_group.add_argument("--nodb", action="store_true", help="Do not add entries to database")

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
    static_inputs['port'] = args.port
    static_inputs['method'] = args.method
    static_inputs['path'] = args.path

    actions = {}
    if args.tools:
        actions['list_tools'] = {}
    if args.resources:
        actions['list_resources'] = {}

    mcpscan(targets, static_inputs, actions, args.workers, args.timeout, args.delay, args.resume)

    DB.stop_worker()
    Output.stop()


def mcpscan(input_targets, static_inputs, actions, workers, timeout, delay, resume):
    args = (actions, timeout)
    dispatch_targets(input_targets, static_inputs, mcpscan_worker, args, workers=workers, delay=delay, resume=resume)


if __name__ == '__main__':
    main()
