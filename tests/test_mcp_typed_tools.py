import asyncio
import importlib.util
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
MCP_INSTALLED = importlib.util.find_spec("mcp") is not None


@unittest.skipUnless(MCP_INSTALLED, "MCP SDK is not installed")
class TypedMCPToolTests(unittest.TestCase):
    def test_all_commands_register_strongly_typed_tools(self):
        from netscan_mcp_server import mcp
        from utils.mcp_runtime import NETSCAN_MODULES

        tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
        expected = {f"netscan_{module}" for module in NETSCAN_MODULES}
        self.assertTrue(expected.issubset(tools))
        general_tools = {
            "netscan_status",
            "netscan_context",
            "netscan_module_help",
            "netscan_list_scans",
            "netscan_scan_status",
            "netscan_cancel_scan",
            "netscan_scan_result",
            "netscan_scan_output",
            "run_netscan",
        }
        self.assertEqual(set(tools), expected | general_tools)

        portscan = tools["netscan_portscan"].input_schema["properties"]
        self.assertEqual(portscan["workers"]["default"], 10)
        self.assertEqual(
            portscan["port"]["anyOf"][0]["items"]["type"], "integer"
        )
        self.assertEqual(
            portscan["service_scan"]["anyOf"][0]["type"], "boolean"
        )

        adscan = tools["netscan_adscan"].input_schema["properties"]
        self.assertEqual(
            set(adscan["ldap_protocol"]["anyOf"][0]["enum"]),
            {"ldap", "ldaps", "gc"},
        )

        smbscan = tools["netscan_smbscan"].input_schema["properties"]
        module_names = set(smbscan["modules"]["anyOf"][0]["items"]["enum"])
        self.assertIn("MS17-010", module_names)
        self.assertIn("PrintSpooler", module_names)
        self.assertIn("module_args", smbscan)


if __name__ == "__main__":
    unittest.main()
