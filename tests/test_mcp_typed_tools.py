import asyncio
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


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
            "netscan_credentials",
            "netscan_run_with_credential",
            "netscan_run_with_credentials",
            "netscan_module_help",
            "netscan_list_scans",
            "netscan_scan_status",
            "netscan_cancel_scan",
            "netscan_scan_result",
            "netscan_scan_output",
            "netscan_scan_artifacts",
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
        self.assertIn(
            "wmiexec", set(smbscan["exec_method"]["anyOf"][0]["enum"])
        )
        self.assertNotIn(
            "atexec", set(smbscan["exec_method"]["anyOf"][0]["enum"])
        )
        self.assertIn("bruteforce", smbscan)
        self.assertIn("ntlm_file", smbscan)
        self.assertIn("processes", smbscan)

        rpcscan = tools["netscan_rpcscan"].input_schema["properties"]
        for argument in ("rpc", "mounts", "list", "uid", "gid", "recurse"):
            self.assertIn(argument, rpcscan)

        es_query = tools["netscan_es_query"].input_schema["properties"]
        self.assertIn("session", es_query)
        self.assertIn("export_bloodhound", es_query)

        for argument in ("domains", "users", "groups", "hosts", "gpos"):
            self.assertIn(argument, adscan)

        winrmscan = tools["netscan_winrmscan"].input_schema["properties"]
        for argument in (
            "port",
            "ssl",
            "bruteforce",
            "simple_bruteforce",
            "username_file",
            "password_file",
            "bruteforce_workers",
            "bruteforce_delay",
            "spray",
            "credential_jitter",
            "spray_round_delay",
            "max_attempts_per_account",
            "continue_on_success",
        ):
            self.assertIn(argument, winrmscan)

        for tool_name in ("netscan_smbscan", "netscan_sshscan"):
            campaign = tools[tool_name].input_schema["properties"]
            for argument in (
                "spray",
                "credential_jitter",
                "spray_round_delay",
                "max_attempts_per_account",
                "continue_on_success",
            ):
                self.assertIn(argument, campaign)

        for tool_name in (
            "netscan_ftpscan",
            "netscan_mongoscan",
            "netscan_mssqlscan",
            "netscan_mysqlscan",
            "netscan_postgrescan",
            "netscan_rdpscan",
            "netscan_redisscan",
            "netscan_snmpscan",
            "netscan_telnetscan",
            "netscan_vncscan",
        ):
            campaign = tools[tool_name].input_schema["properties"]
            for argument in (
                "spray",
                "credential_jitter",
                "spray_round_delay",
                "max_attempts_per_account",
                "continue_on_success",
            ):
                self.assertIn(argument, campaign)

    def test_stored_credential_secret_is_only_in_subprocess_environment(self):
        import netscan_mcp_server as server

        credential = {
            "credential_id": "cred_example",
            "session": "engagement-42",
            "kind": "password",
            "username": "alice",
            "domain": "example.local",
            "_secret": "HighlySecret!",
        }
        with (
            patch.object(server.CREDENTIAL_CATALOG, "resolve", return_value=credential),
            patch.object(
                server.JOB_MANAGER,
                "start",
                return_value={"scan_id": "scan-1", "state": "queued"},
            ) as start,
        ):
            result = asyncio.run(
                server.netscan_run_with_credential(
                    "smbscan", "192.0.2.0/24", "cred_example"
                )
            )

        positional, keyword = start.call_args
        self.assertNotIn("HighlySecret!", repr(positional))
        self.assertEqual(
            keyword["secret_environment"]["NETSCAN_MCP_CREDENTIAL_PASSWORD"],
            "HighlySecret!",
        )
        self.assertEqual(
            keyword["context"]["credential"]["credential_id"], "cred_example"
        )
        self.assertNotIn("HighlySecret!", repr(result))

    def test_stored_credential_batch_starts_one_traceable_job_per_id(self):
        import netscan_mcp_server as server

        def resolve(identifier, session=None):
            return {
                "credential_id": identifier,
                "session": session or "engagement-42",
                "kind": "password",
                "username": identifier,
                "_secret": f"secret-for-{identifier}",
            }

        with (
            patch.object(server.CREDENTIAL_CATALOG, "resolve", side_effect=resolve),
            patch.object(
                server.JOB_MANAGER,
                "start",
                side_effect=[
                    {"scan_id": "scan-1", "state": "queued"},
                    {"scan_id": "scan-2", "state": "queued"},
                ],
            ) as start,
        ):
            result = asyncio.run(
                server.netscan_run_with_credentials(
                    "winrmscan",
                    "192.0.2.0/24",
                    ["cred_one", "cred_two"],
                )
            )

        self.assertEqual(result["count"], 2)
        self.assertEqual(start.call_count, 2)
        self.assertFalse(result["secrets_disclosed"])
        self.assertNotIn("secret-for", repr(result))


if __name__ == "__main__":
    unittest.main()
