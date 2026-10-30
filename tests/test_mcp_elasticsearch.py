import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from utils.mcp_elasticsearch import elasticsearch_context  # noqa: E402


class MCPElasticsearchTests(unittest.TestCase):
    def test_context_has_session_handoff_without_credentials(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "config.cfg"
            config.write_text(
                """[Global]
session = engagement-42
[Elasticsearch]
enabled = true
index = Results
host = elastic.internal
port = 9243
ssl = true
username = analyst
password = highly-secret
mcp_url = http://kibana:5601/api/agent_builder/mcp
enable_file_storage = false
""",
                encoding="utf-8",
            )
            context = elasticsearch_context(config_path=config)

        self.assertEqual(context["index"], "results")
        self.assertEqual(context["session"], "engagement-42")
        self.assertEqual(context["endpoint"], "https://elastic.internal:9243")
        self.assertTrue(context["credentials_configured"])
        self.assertNotIn("username", context)
        self.assertNotIn("password", context)
        self.assertNotIn("highly-secret", repr(context))
        self.assertEqual(
            context["analysis_handoff"]["required_scope"]["session"],
            "engagement-42",
        )


if __name__ == "__main__":
    unittest.main()
