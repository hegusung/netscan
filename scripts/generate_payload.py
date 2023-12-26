#!/usr/bin/python3

import argparse
from utils.utils import normalize_path
from server.payload_manager import PayloadManager
from server.ressources import get_ressource_md5, list_ressources

def main():
    parser = argparse.ArgumentParser(description='Generate payload')
    parser.add_argument('-l', help='List available payloads', action='store_true', dest='list')
    parser.add_argument('-p', help='Use payload', type=str, nargs='+', dest='payload')
    parser.add_argument('-o', help='Output file', type=str, nargs='?', dest='output')

    args = parser.parse_args()

    modules = PayloadManager.list_payloads()

    if args.list:
        print("Available payloads:")
        for name, module in modules.items():
            print(" - [%s] %s %s" % (module.type, module.name, ' '.join(['<%s>' % s for s in module.args])))
        return
    else:
        if args.payload[0].lower() in modules:
            payload = PayloadManager.generate_payload(args.payload[0], args.payload[1:])
        else:
            print('Incorrect payload')
            return

        if args.output:
            f = open(normalize_path(args.output), 'wb')
            if type(payload) == bytes:
                f.write(payload)
            else:
                f.write(payload.encode())
            f.close()
            print("Payload written to %s" % args.output)
        else:
            print(payload)

if __name__ == '__main__':
    main()
