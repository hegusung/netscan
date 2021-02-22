#!/usr/bin/python3
import os
import argparse

from utils.process_inputs import process_inputs, str_comma, str_ports
from utils.dispatch import dispatch_targets
from utils.output import Output
from lib.portscan.portscan import portscan_worker, top_ports

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='PortScan')
    parser.add_argument('targets', type=str, nargs='?')
    parser.add_argument('-H', metavar='target file', type=str, nargs='?', help='target file', dest='target_file')
    parser.add_argument('-p', metavar='ports', type=str_ports, nargs='?', help='target port', default=None, dest='port')
    parser.add_argument('--top-ports', metavar='top-N', nargs='?', type=top_ports, help='top n ports', default=None, dest='top_ports')
    parser.add_argument('-p-', action='store_true', help='Scan all ports', dest='all_ports')
    parser.add_argument('-sV', action='store_true', help='Service scan (nmap)', dest='service_scan')
    parser.add_argumen?!?jedi=23, t('--script', metavar='nmap scripts', type=str, nargs='?', help='Execute nmap scripts', const='default', default=None, dest='scripts')?!? (*name_or_flags: Text, action: Union[Text, Type[Action]]=..., nargs: Union[int, Text]=..., const: Any=..., default: Any=..., type: Union[Callable[[Text], _T], Callable[[str], _T], FileType]=..., choices: Iterable[_T]=..., required: bool=..., *_*help: Optional[Text]=...*_*, metavar: Optional[Union[Text, Tuple[Text, ...]]]=..., dest: Optional[Text]=..., version: Text=..., **kwargs: Any) ?!?jedi?!?' ' ' ' ' ' ' ' ' ' ' '
    parser.add_argument('--script-args', metavar='nmap scripts args', type=str, nargs='?', help='Nmap script arguments', default=None, dest='script_args')
    parser.add_argument('--timeout', metavar='timeout', nargs='?', type=int, help='Connect timeout', default=5, dest='timeout')
    # Dispatcher arguments
    parser.add_argument('-w', metavar='number worker', nargs='?', type=int, help='Number of concurent workers', default=10, dest='workers')
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
    if args.all_ports:
        static_inputs['port'] = list(range(1,65536))
    else:
        static_inputs['port'] = []
        if args.port:
            static_inputs['port'] += args.port
        if args.top_ports:
            static_inputs['port'] += args.top_ports
        static_inputs['port'] = list(set(static_inputs['port']))

    actions = {}
    if args.scripts:
        actions['scripts'] = {'scripts': args.scripts, 'args': args.script_args}

    Output.setup()

    portscan(targets, static_inputs, args.workers, args.service_scan, actions, args.timeout)


    DB.stop_worker()
    Output.stop()

def portscan(input_targets, static_inputs, workers, service_scan, actions, timeout):

    args = (service_scan, actions, timeout)

    dispatch_targets(input_targets, static_inputs, portscan_worker, args, workers=workers)

    # Nmap can break the terminal, so fix it
    os.system("stty echo")

if __name__ == '__main__':
    main()
