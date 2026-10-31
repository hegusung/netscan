import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from utils.events import normalize_output_event  # noqa: E402


class NormalizedEventTests(unittest.TestCase):
    def test_legacy_vulnerability_is_normalized(self):
        event = normalize_output_event(
            {"type": "vuln", "target": "https://example.test", "message": "TLS issue"}
        )
        self.assertEqual(event["schema_version"], 1)
        self.assertEqual(event["category"], "vulnerability")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["target"], "https://example.test")

    def test_explicit_event_is_idempotent(self):
        original = normalize_output_event(
            {
                "type": "success",
                "target": "ssh://192.0.2.1:22",
                "message": "Authentication success for alice",
                "event": {
                    "category": "authentication",
                    "status": "success",
                    "data": {"protocol": "ssh", "username": "alice"},
                },
            }
        )
        normalized_again = normalize_output_event(original)
        self.assertEqual(normalized_again["category"], "authentication")
        self.assertEqual(normalized_again["status"], "success")
        self.assertEqual(normalized_again["data"]["protocol"], "ssh")


if __name__ == "__main__":
    unittest.main()
