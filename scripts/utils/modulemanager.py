import os
import importlib

class ModuleManager:
    def __init__(self, module_path):
        self.module_path = module_path
        self.abs_module_path = os.path.join(os.path.dirname(__file__), '..', self.module_path)
        self.modules = {}

        self.load_modules()

    def load_modules(self):
        package = self.module_path.replace('/', '.')
        mods = [".%s" % f[:-3] for f in os.listdir(self.abs_module_path) if f.endswith(".py") and f != "__init__.py"]
        for mod in mods:
            m = getattr(importlib.import_module(mod, package), "Module")()
            self.modules[m.name.lower()] = m

    def list_modules(self):
        modules = []
        for _, module in self.modules.items():
            modules.append({
                'name': module.name,
                'description': module.description,
            })

        return modules

    def execute_modules(self, module_names, args):
        mods = [m.lower().strip() for m in module_names.split(',')]
        for name, module in self.modules.items():
            if name in mods:
                module.run(*args)


