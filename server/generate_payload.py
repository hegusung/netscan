#!/usr/bin/python3

import argparse
from payload_manager import PayloadManager
from ressources import get_ressource_md5, list_ressources

def main():
    parser = argparse.ArgumentParser(description='Generate payload')
    parser.add_argument('-l', help='List available payloads', action='store_true', dest='list')
    parser.add_argument('-p', help='Use payload', type=str, nargs='+', dest='payload')

    args = parser.parse_args()

    modules = PayloadManager.list_payloads()

    if args.list:
        print("Available payloads:")
        for name, module in modules.items():
            print(" - %s %s" % (module.name, ' '.join(module.args)))
        return
    else:
        if args.payload[0].lower() in modules:
            payload = PayloadManager.generate_payload(args.payload[0], args.payload[1:])
        else:
            print('Incorrect payload')
            return

        print(payload)

if __name__ == '__main__':
    main()
