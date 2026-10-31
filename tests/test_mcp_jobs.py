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
from pathlib import Path
print('scanner output')
print('Authentication success with password HighlySecret!')
with open(os.environ['NETSCAN_MCP_EVENT_FILE'], 'a') as output:
    output.write(json.dumps({'type': 'vuln', 'target': '192.0.2.1', 'message': 'test finding'}) + '\\n')
with open(os.environ['NETSCAN_MCP_DB_RESULT_FILE'], 'w') as output:
    json.dump({'session': 'test', 'documents_processed': 2, 'documents_indexed': 2, 'documents_failed': 0, 'documents_written_to_file': 0, 'persistence_disabled': False}, output)
Path(os.environ['NETSCAN_MCP_ARTIFACT_DIR'], 'report.json').write_text('{"ok": true}')
""",
                encoding="utf-8",
            )
            manager = ScanJobManager(
                max_workers=1,
                retention=10,
                output_limit=1000,
                state_dir=root / "state",
            )
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
                self.assertNotIn(
                    "HighlySecret!", manager.output_text(started["scan_id"])
                )
                artifacts = manager.list_artifacts(started["scan_id"])
                self.assertEqual(artifacts["count"], 1)
                artifact = artifacts["artifacts"][0]
                self.assertEqual(artifact["name"], "report.json")
                self.assertEqual(
                    manager.artifact_bytes(started["scan_id"], artifact["artifact_id"]),
                    b'{"ok": true}',
                )
            finally:
                manager.shutdown(wait=True)

    def test_es_query_export_is_confined_to_the_job_artifact_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts = root / "scripts"
            scripts.mkdir()
            requested = root / "operator-requested-output"
            requested.mkdir()
            (scripts / "es_query.py").write_text(
                """import pathlib, sys
destination = pathlib.Path(sys.argv[sys.argv.index('--export-bloodhound') + 1])
destination.mkdir(parents=True, exist_ok=True)
(destination / 'bloodhound.json').write_text('{"data": []}')
""",
                encoding="utf-8",
            )
            manager = ScanJobManager(
                max_workers=1, retention=10, state_dir=root / "state"
            )
            try:
                with (
                    patch.object(mcp_runtime, "PROJECT_ROOT", root),
                    patch.object(mcp_runtime, "SCRIPTS_DIR", scripts),
                    patch.object(mcp_jobs, "PROJECT_ROOT", root),
                    patch.dict(os.environ, {"NETSCAN_MCP_ENABLE_RUN": "true"}),
                ):
                    started = manager.start(
                        "es_query", ["--export-bloodhound", str(requested)], 5
                    )
                    self._wait(manager, started["scan_id"])

                self.assertEqual(list(requested.iterdir()), [])
                artifacts = manager.list_artifacts(started["scan_id"])["artifacts"]
                self.assertEqual(len(artifacts), 1)
                self.assertEqual(artifacts[0]["relative_path"], "bloodhound/bloodhound.json")
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
            manager = ScanJobManager(
                max_workers=1, retention=10, state_dir=root / "state"
            )
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

    def test_completed_job_survives_manager_restart(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "portscan.py").write_text(
                """import os
from pathlib import Path
print('persistent output')
Path(os.environ['NETSCAN_MCP_ARTIFACT_DIR'], 'persistent.json').write_text('{}')
""",
                encoding="utf-8",
            )
            state_dir = root / "state"
            manager = ScanJobManager(max_workers=1, retention=10, state_dir=state_dir)
            with (
                patch.object(mcp_runtime, "PROJECT_ROOT", root),
                patch.object(mcp_runtime, "SCRIPTS_DIR", scripts),
                patch.object(mcp_jobs, "PROJECT_ROOT", root),
                patch.dict(os.environ, {"NETSCAN_MCP_ENABLE_RUN": "true"}),
            ):
                started = manager.start(
                    "portscan",
                    ["192.0.2.1"],
                    5,
                    context={"credential": {"credential_id": "cred_example"}},
                )
                self._wait(manager, started["scan_id"])
            manager.shutdown(wait=True)

            restored = ScanJobManager(max_workers=1, retention=10, state_dir=state_dir)
            try:
                status = restored.status(started["scan_id"])
                self.assertEqual(status["state"], "succeeded")
                self.assertEqual(status["argument_count"], 1)
                self.assertEqual(
                    status["context"]["credential"]["credential_id"],
                    "cred_example",
                )
                self.assertIn("persistent output", restored.output_text(started["scan_id"]))
                artifacts = restored.list_artifacts(started["scan_id"])
                self.assertEqual(artifacts["artifacts"][0]["name"], "persistent.json")
            finally:
                restored.shutdown(wait=True)

    def test_active_persisted_job_is_not_replayed_after_restart(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state = Path(temp_dir) / "state"
            job_dir = state / "jobs" / "interrupted"
            job_dir.mkdir(parents=True)
            (job_dir / "job.json").write_text(
                json.dumps(
                    {
                        "scan_id": "interrupted",
                        "module": "smbscan",
                        "argument_count": 3,
                        "timeout_seconds": 300,
                        "elasticsearch": {"persistence_expected": True},
                        "state": "running",
                    }
                ),
                encoding="utf-8",
            )

            manager = ScanJobManager(max_workers=1, retention=10, state_dir=state)
            try:
                status = manager.status("interrupted")
                self.assertEqual(status["state"], "failed")
                self.assertIn("restarted", status["internal_error"])
                self.assertEqual(manager.list()[0]["scan_id"], "interrupted")
            finally:
                manager.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
