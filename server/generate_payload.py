#!/usr/bin/python3

import argparse
import os
import importlib
from ressources import get_ressource_md5, list_ressources

def main():
    parser = argparse.ArgumentParser(description='Generate payload')
    parser.add_argument('ip', help='Listening IP', type=str)
    parser.add_argument('port', help='Listening port', type=int, nargs='?', default=8000)
    parser.add_argument('-l', help='List available payloads', action='store_true', dest='list')
    parser.add_argument('-p', help='Use payload', type=str, dest='payload')

    args = parser.parse_args()

    modules = load_modules()

    if args.list:
        print("Available payloads:")
        for name, module in modules.items():
            print(" - %s" % module.name)
        return
    else:
        http_url = 'http://%s:%d' % (args.ip, args.port)

        if args.payload.lower() and args.payload in modules:
            payload = modules[args.payload].generate_payload(http_url)
        else:
            print('Incorrect payload')
            return

        print(payload)

def load_modules():
    module_dict = {}

    path = os.path.join(os.path.dirname(__file__), 'payloads')
    for module_filename in os.listdir(path):
        if module_filename[-3:] == '.py':
            p = os.path.join(path, module_filename)
            mod = importlib.import_module('payloads.%s' % module_filename[:-3])
            module_class = getattr(mod, "Payload")
            module_dict[module_class.name.lower()] = module_class()

    return module_dict



if __name__ == '__main__':
    main()
