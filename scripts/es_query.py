#!/usr/bin/env python3

import argparse
from utils.utils import normalize_path
from utils.output import Output
from utils.db import DB
from utils.config import Config
from lib.es_query.es_query import dump, export_ports, export_hashes, export_bloodhound, restore

def main():
    parser = argparse.ArgumentParser(description='Elasticsearch Query: make target list out of elasticsearch')
    parser.add_argument('-s', metavar='session', type=str, nargs='?', help='session', dest='session')
    parser.add_argument('--service', metavar='service', type=str, nargs='?', help='service', dest='service')
    parser.add_argument('--export', metavar='output directory', type=str, nargs='?', help='Directory to export ip:port files to', dest='export_ports')
    parser.add_argument('--export-hashes', metavar='output directory', type=str, nargs='?', help='Directory to export hashes files to', dest='export_hashes')
    parser.add_argument('--export-bloodhound', metavar='output directory', type=str, nargs='?', help='Directory to export bloodhound files to', dest='export_bloodhound')
    parser.add_argument('--dump', metavar='output file', type=str, nargs='?', help='Dump elastisearch to file', dest='dump')
    parser.add_argument('--restore', metavar='input file', type=str, nargs='?', help='Restore dump from file', dest='restore')

    args = parser.parse_args()

    Config.load_config()

    if args.session is None:
        session = Config.config.get('Global', 'session')
    else:
        session = args.session

    Output.setup()
    DB.start_worker(False, session=session)

    if args.export_ports:
        export_ports(session, args.service, normalize_path(args.export_ports))
    if args.export_hashes:
        export_hashes(session, args.service, normalize_path(args.export_hashes))
    if args.export_bloodhound:
        export_bloodhound(session, normalize_path(args.export_bloodhound))
    elif args.dump:
        dump(session, normalize_path(args.dump))
    elif args.restore:
        restore(session, normalize_path(args.restore))

    DB.stop_worker()
    Output.stop()


if __name__ == '__main__':
    main()
