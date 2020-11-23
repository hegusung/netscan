#!/usr/bin/python3
import os
import argparse

from utils.output import Output
from lib.es_query.es_query import export

from utils.db import DB
from utils.config import Config

def main():
    parser = argparse.ArgumentParser(description='Elasticsearch Query: make target list out of elasticsearch')
    parser.add_argument('-s', metavar='session', type=str, nargs='?', help='session', dest='session')
    parser.add_argument('--service', metavar='service', type=str, nargs='?', help='service', dest='service')
    parser.add_argument('--dir', metavar='output directory', type=str, nargs='?', help='Directory to export files to', dest='directory')

    args = parser.parse_args()

    Config.load_config()

    export(args.session, args.service, args.directory)

if __name__ == '__main__':
    main()
