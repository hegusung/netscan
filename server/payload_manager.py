import os
import importlib

class PayloadManager:

    @classmethod
    def list_payloads(self):
        module_dict = {}

        path = os.path.join(os.path.dirname(__file__), 'payloads')
        for module_filename in os.listdir(path):
            if module_filename[-3:] == '.py':
                p = os.path.join(path, module_filename)
                try:
                    mod = importlib.import_module('server.payloads.%s' % module_filename[:-3])
                except ModuleNotFoundError:
                    mod = importlib.import_module('payloads.%s' % module_filename[:-3])
                module_class = getattr(mod, "Payload")
                module_dict[module_class.name.lower()] = module_class()

        return module_dict

    @classmethod
    def generate_payload(self, payload_name, payload_args):
        payloads = self.list_payloads()

        module = payloads[payload_name.lower()]

        return module.generate_payload(*payload_args)

