#!/usr/bin/env python3

import argparse
from utils.utils import normalize_path
from utils.output import Output
from utils.db import DB
from utils.config import Config
from lib.es_query.es_query import dump, export_ports, export_hashes, export_bloodhound, restore, delete_session, get_gpos_admins, parse_spns, enrich_gpos
from lib.es_query.bloodhound_automation import set_owned
from utils.argparse_format import ColoredSelectiveDefaultsHelpFormatter


def main():
    parser = argparse.ArgumentParser(description='Elasticsearch Query: make target list out of elasticsearch', formatter_class=ColoredSelectiveDefaultsHelpFormatter)
    parser.add_argument('-s', metavar='session', type=str, nargs='?', help='session', dest='session')
    parser.add_argument('--service', metavar='service', type=str, nargs='?', help='service', dest='service')

    export_group = parser.add_argument_group("Export")
    export_group.add_argument('--export', metavar='output directory', type=str, nargs='?', help='Directory to export ip:port files to', dest='export_ports')
    export_group.add_argument('--export-hashes', metavar='output directory', type=str, nargs='?', help='Directory to export hashes files to', dest='export_hashes')
    export_group.add_argument('--export-bloodhound', metavar='output directory', type=str, nargs='?', help='Directory to export bloodhound files to', dest='export_bloodhound')
    export_group.add_argument('--parse-spns', metavar='output directory', type=str, nargs='?', help='Parse SPNs and save them as files', dest='parse_spns')

    backup_group = parser.add_argument_group("Backup / Restore / Delete session")
    backup_group.add_argument('--dump', metavar='output file', type=str, nargs='?', help='Dump elastisearch to file', dest='dump')
    backup_group.add_argument('--restore', metavar='input file', type=str, nargs='?', help='Restore dump from file', dest='restore')
    backup_group.add_argument('--delete-session', metavar='session', type=str, nargs='?', help='Delete all documents related to a specific session', dest='delete_session')
    
    enrichment_group = parser.add_argument_group("Elastic & Bloodhound data enrichment")
    enrichment_group.add_argument('--owned', action='store_true', help='Queries Neo4j to set owned users and computers as "owned"', dest='owned')
    enrichment_group.add_argument('--enrich-gpos', action='store_true', help='Enrich Elasticsearch GPO data with affected computers', dest='enrich_gpos')
    enrichment_group.add_argument('--gpos-admins', action='store_true', help='Lists administrators based on GPOs', dest='gpo_admins')

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
    elif args.delete_session:
        delete_session(args.delete_session)
    elif args.parse_spns:
        parse_spns(session, normalize_path(args.parse_spns))
    # Bloodhound 
    if args.owned:
        set_owned(session)
    if args.enrich_gpos:
        enrich_gpos(session)
    if args.gpo_admins:
        get_gpos_admins(session)

    DB.stop_worker()
    Output.stop()


if __name__ == '__main__':
    main()
