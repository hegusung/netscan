import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from utils import mcp_runtime  # noqa: E402
from utils.mcp_runtime import (  # noqa: E402
    MCPRuntimeError,
    allowed_modules,
    run_module,
    validate_arguments,
    validate_module,
)


class MCPRuntimeTests(unittest.TestCase):
    def test_default_module_allowlist_contains_all_netscan_commands(self):
        modules = allowed_modules()
        self.assertIn("portscan", modules)
        self.assertIn("server", modules)
        self.assertIn("generate_payload", modules)
        self.assertIn("es_query", modules)
        self.assertIn("rsh_listener", modules)
        self.assertNotIn("netscan_mcp_server", modules)

    def test_configured_allowlist_can_only_restrict_defaults(self):
        with patch.dict(os.environ, {"NETSCAN_MCP_ALLOWED_MODULES": "portscan,whoisscan"}):
            self.assertEqual(allowed_modules(), ("portscan", "whoisscan"))

        with patch.dict(os.environ, {"NETSCAN_MCP_ALLOWED_MODULES": "not_a_module"}):
            with self.assertRaises(MCPRuntimeError):
                allowed_modules()

    def test_module_names_cannot_escape_scripts_directory(self):
        with self.assertRaises(MCPRuntimeError):
            validate_module("../server_data/payloads/invoke_mimikatz")

    def test_arguments_are_argv_values_not_a_command_string(self):
        arguments = ["example.test; touch /tmp/not-created", "--nodb"]
        self.assertEqual(validate_arguments(arguments), arguments)
        with self.assertRaises(MCPRuntimeError):
            validate_arguments("example.test --nodb")

    def test_execution_requires_explicit_operator_opt_in(self):
        with patch.dict(os.environ, {"NETSCAN_MCP_ENABLE_RUN": "false"}):
            with self.assertRaisesRegex(MCPRuntimeError, "execution is disabled"):
                run_module("portscan", ["127.0.0.1", "--nodb"], 1)

    def test_execution_uses_argv_without_a_shell(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "portscan.py").write_text(
                "import sys\nprint(repr(sys.argv[1:]))\n", encoding="utf-8"
            )
            marker = root / "shell-was-used"
            argument = f"target; touch {marker}"

            with (
                patch.object(mcp_runtime, "PROJECT_ROOT", root),
                patch.object(mcp_runtime, "SCRIPTS_DIR", scripts),
                patch.dict(os.environ, {"NETSCAN_MCP_ENABLE_RUN": "true"}),
            ):
                result = run_module("portscan", [argument], 5)

            self.assertEqual(result.exit_code, 0)
            self.assertIn(argument, result.output)
            self.assertFalse(marker.exists())

    def test_output_is_bounded_while_process_runs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "portscan.py").write_text(
                "print('x' * 10000)\n", encoding="utf-8"
            )

            with (
                patch.object(mcp_runtime, "PROJECT_ROOT", root),
                patch.object(mcp_runtime, "SCRIPTS_DIR", scripts),
                patch.dict(
                    os.environ,
                    {
                        "NETSCAN_MCP_ENABLE_RUN": "true",
                        "NETSCAN_MCP_MAX_OUTPUT": "64",
                    },
                ),
            ):
                result = run_module("portscan", [], 5)

            self.assertTrue(result.truncated)
            self.assertLess(len(result.output), 128)
            self.assertIn("output truncated", result.output)

    def test_timed_out_process_is_terminated(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "portscan.py").write_text(
                "import time\ntime.sleep(10)\n", encoding="utf-8"
            )

            with (
                patch.object(mcp_runtime, "PROJECT_ROOT", root),
                patch.object(mcp_runtime, "SCRIPTS_DIR", scripts),
                patch.dict(os.environ, {"NETSCAN_MCP_ENABLE_RUN": "true"}),
            ):
                result = run_module("portscan", [], 1)

            self.assertTrue(result.timed_out)
            self.assertNotEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
