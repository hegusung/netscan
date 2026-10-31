import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from utils.argparse_schema import (  # noqa: E402
    ArgumentSchemaError,
    extract_argument_specs,
    extract_module_specs,
    values_to_argv,
)
from utils.mcp_runtime import NETSCAN_MODULES  # noqa: E402


class ArgparseSchemaTests(unittest.TestCase):
    def specs(self, module):
        return extract_argument_specs(PROJECT_ROOT / "scripts" / f"{module}.py")

    def test_every_argparse_action_is_extracted(self):
        all_specs = {module: self.specs(module) for module in NETSCAN_MODULES}
        self.assertEqual(sum(len(specs) for specs in all_specs.values()), 471)
        for specs in all_specs.values():
            destinations = [spec.dest for spec in specs]
            self.assertEqual(len(destinations), len(set(destinations)))

    def test_portscan_types_and_documentation(self):
        specs = {spec.dest: spec for spec in self.specs("portscan")}
        self.assertEqual(specs["port"].value_type, "str_ports")
        self.assertEqual(specs["workers"].value_type, "int")
        self.assertEqual(specs["delay"].value_type, "float")
        self.assertEqual(specs["service_scan"].action, "store_true")
        self.assertIn("Service scan", specs["service_scan"].help)
        self.assertEqual(specs["workers"].typed_default, 10)
        self.assertFalse(specs["service_scan"].typed_default)

    def test_custom_converter_defaults_are_typed(self):
        specs = {spec.dest: spec for spec in self.specs("httpscan")}
        self.assertEqual(specs["port"].typed_default, [80, 443])
        self.assertEqual(set(specs["method"].typed_default), {"http", "https"})

    def test_choices_are_preserved(self):
        ad_specs = {spec.dest: spec for spec in self.specs("adscan")}
        self.assertEqual(ad_specs["ldap_protocol"].choices, ("gc", "ldap", "ldaps"))

    def test_typed_values_convert_to_native_argv(self):
        argv = values_to_argv(
            self.specs("portscan"),
            {
                "targets": "192.0.2.0/24",
                "port": [22, 80, 443],
                "workers": 20,
                "service_scan": True,
                "nodb": False,
            },
        )
        self.assertEqual(
            argv,
            ["192.0.2.0/24", "-p", "22,80,443", "-sV", "-w", "20"],
        )

    def test_multi_value_arguments_remain_separate(self):
        argv = values_to_argv(
            self.specs("generate_payload"),
            {"payload": ["reversetcp_powershell", "192.0.2.10", "4444"]},
        )
        self.assertEqual(
            argv,
            ["-p", "reversetcp_powershell", "192.0.2.10", "4444"],
        )

    def test_nested_module_catalogs_are_extracted(self):
        expected_counts = {
            "adscan": 4,
            "httpscan": 24,
            "rdpscan": 1,
            "smbscan": 8,
            "sshscan": 9,
        }
        for scanner, expected_count in expected_counts.items():
            modules = extract_module_specs(
                PROJECT_ROOT / "scripts" / "lib" / scanner / "modules"
            )
            self.assertEqual(len(modules), expected_count)
            self.assertTrue(all(module.name and module.description for module in modules))

        smb_modules = extract_module_specs(
            PROJECT_ROOT / "scripts" / "lib" / "smbscan" / "modules"
        )
        by_name = {module.name: module for module in smb_modules}
        self.assertIn("EternalBlue", by_name["MS17-010"].description)

    def test_nested_modules_and_arguments_use_native_cli_encoding(self):
        argv = values_to_argv(
            self.specs("smbscan"),
            {"targets": "192.0.2.10", "modules": ["MS17-010", "PrintSpooler"]},
            module_args=["192.0.2.20"],
        )
        self.assertEqual(
            argv,
            ["192.0.2.10", "-m", "MS17-010,PrintSpooler", "192.0.2.20"],
        )

    def test_module_arguments_require_a_selected_module(self):
        with self.assertRaisesRegex(ArgumentSchemaError, "requires"):
            values_to_argv(
                self.specs("smbscan"),
                {"modules": None},
                module_args=["192.0.2.20"],
            )


if __name__ == "__main__":
    unittest.main()
