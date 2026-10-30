import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from utils import mcp_jobs, mcp_runtime  # noqa: E402
from utils.mcp_jobs import ScanJobManager  # noqa: E402


class MCPJobTests(unittest.TestCase):
    def _wait(self, manager, scan_id, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = manager.status(scan_id)
            if status["state"] not in ("queued", "running"):
                return status
            time.sleep(0.02)
        self.fail("background scan did not finish")

    def test_background_job_returns_structured_result_and_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "portscan.py").write_text(
                """import json, os
print('scanner output')
with open(os.environ['NETSCAN_MCP_EVENT_FILE'], 'a') as output:
    output.write(json.dumps({'type': 'vuln', 'target': '192.0.2.1', 'message': 'test finding'}) + '\\n')
with open(os.environ['NETSCAN_MCP_DB_RESULT_FILE'], 'w') as output:
    json.dump({'session': 'test', 'documents_processed': 2, 'documents_indexed': 2, 'documents_failed': 0, 'documents_written_to_file': 0, 'persistence_disabled': False}, output)
""",
                encoding="utf-8",
            )
            manager = ScanJobManager(max_workers=1, retention=10, output_limit=1000)
            try:
                with (
                    patch.object(mcp_runtime, "PROJECT_ROOT", root),
                    patch.object(mcp_runtime, "SCRIPTS_DIR", scripts),
                    patch.object(mcp_jobs, "PROJECT_ROOT", root),
                    patch.dict(os.environ, {"NETSCAN_MCP_ENABLE_RUN": "true"}),
                ):
                    started = manager.start("portscan", ["192.0.2.1"], 5)
                    self.assertIn(started["state"], ("queued", "running"))
                    finished = self._wait(manager, started["scan_id"])

                self.assertEqual(finished["state"], "succeeded")
                result = manager.result(started["scan_id"])
                self.assertEqual(result["summary"]["vulnerabilities"], 1)
                self.assertEqual(result["findings"][0]["target"], "192.0.2.1")
                self.assertEqual(
                    result["elasticsearch"]["run"]["documents_indexed"], 2
                )
                self.assertIn("scanner output", manager.output_text(started["scan_id"]))
            finally:
                manager.shutdown(wait=True)

    def test_running_job_can_be_cancelled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "portscan.py").write_text(
                "import time\nprint('started', flush=True)\ntime.sleep(30)\n",
                encoding="utf-8",
            )
            manager = ScanJobManager(max_workers=1, retention=10)
            try:
                with (
                    patch.object(mcp_runtime, "PROJECT_ROOT", root),
                    patch.object(mcp_runtime, "SCRIPTS_DIR", scripts),
                    patch.object(mcp_jobs, "PROJECT_ROOT", root),
                    patch.dict(os.environ, {"NETSCAN_MCP_ENABLE_RUN": "true"}),
                ):
                    started = manager.start("portscan", [], 20)
                    deadline = time.monotonic() + 2
                    while manager.status(started["scan_id"])["state"] == "queued":
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.01)
                    manager.cancel(started["scan_id"])
                    finished = self._wait(manager, started["scan_id"])
                self.assertEqual(finished["state"], "cancelled")
            finally:
                manager.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
