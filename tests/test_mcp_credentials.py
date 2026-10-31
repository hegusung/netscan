import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from utils.mcp_credentials import CredentialCatalog  # noqa: E402


class FakeCatalog(CredentialCatalog):
    def _documents(self, session=None):
        return "pentest", [
            {
                "_id": "elasticsearch-id-containing-secret-material",
                "_source": {
                    "doc_type": "domain_password",
                    "session": session or "engagement-42",
                    "domain": "example.local",
                    "username": "alice",
                    "password": "HighlySecret!",
                },
            }
        ]


class MCPCredentialTests(unittest.TestCase):
    def test_catalog_returns_opaque_stable_ids_without_secrets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state = Path(temp_dir)
            first = FakeCatalog(state_dir=state)
            listed = first.list(session="engagement-42")
            identifier = listed["credentials"][0]["credential_id"]
            second = FakeCatalog(state_dir=state)
            repeated = second.list(session="engagement-42")

        self.assertTrue(identifier.startswith("cred_"))
        self.assertEqual(identifier, repeated["credentials"][0]["credential_id"])
        self.assertNotIn("HighlySecret!", repr(listed))
        self.assertNotIn("elasticsearch-id", repr(listed))
        self.assertFalse(listed["secrets_returned"])

    def test_resolve_keeps_secret_internal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            catalog = FakeCatalog(state_dir=Path(temp_dir))
            identifier = catalog.list()["credentials"][0]["credential_id"]
            resolved = catalog.resolve(identifier)

        self.assertEqual(resolved["_secret"], "HighlySecret!")
        self.assertNotIn("_secret", catalog._public(resolved))


if __name__ == "__main__":
    unittest.main()
