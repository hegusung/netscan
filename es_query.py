#!/usr/bin/python3
import os
import argparse

from utils.output import Output
from lib.es_query.es_query import export, dump, restore

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='Elasticsearch Query: make target list out of elasticsearch')
    parser.add_argument('-s', metavar='session', type=str, nargs='?', help='session', dest='session')
    parser.add_argument('--service', metavar='service', type=str, nargs='?', help='service', dest='service')
    parser.add_argument('--dir', metavar='output directory', type=str, nargs='?', help='Directory to export files to', dest='directory')
    parser.add_argument('--dump', metavar='output file', type=str, nargs='?', help='Dump elastisearch to file', dest='dump')
    parser.add_argument('--restore', metavar='input file', type=str, nargs='?', help='Restore dump from file', dest='restore')

    args = parser.parse_args()

    Config.load_config()

    if args.session == None:
        session = Config.config.get('Global', 'session')
    else:
        session = args.session

    Output.setup()
    DB.start_worker(False, session=session)

    if args.directory:
        export(session, args.service, args.directory)
    elif args.dump:
        dump(session, args.dump)
    elif args.restore:
        restore(session, args.restore)

    DB.stop_worker()
    Output.stop()

if __name__ == '__main__':
    main()
