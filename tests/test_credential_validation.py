import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from utils.db import DB  # noqa: E402


class CredentialValidationTests(unittest.TestCase):
    def test_credential_insert_emits_secret_free_validation(self):
        DB.session = "engagement-42"
        credential = {
            "host": "192.0.2.1",
            "port": 22,
            "service": "ssh",
            "url": "ssh://192.0.2.1:22",
            "username": "alice",
            "password": "HighlySecret!",
        }
        with patch.object(DB, "send") as send:
            DB.insert_credential(credential)

        validation = send.call_args_list[0].args[0]
        persisted_credential = send.call_args_list[1].args[0]
        self.assertEqual(validation["doc_type"], "credential_validation")
        self.assertEqual(validation["status"], "success")
        self.assertEqual(
            validation["credential_ref"], persisted_credential["credential_ref"]
        )
        self.assertNotIn("password", validation)
        self.assertNotIn("HighlySecret!", repr(validation))

    def test_reference_is_session_scoped_and_stable(self):
        DB.session = "engagement-42"
        first = DB.credential_reference(None, "alice", "password", "Secret!")
        second = DB.credential_reference(None, "alice", "password", "Secret!")
        DB.session = "another-engagement"
        third = DB.credential_reference(None, "alice", "password", "Secret!")
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)

    def test_community_uses_password_storage_without_losing_its_kind(self):
        DB.session = "engagement-42"
        with patch.object(DB, "send") as send:
            DB.insert_credential(
                {
                    "host": "192.0.2.10",
                    "port": 161,
                    "url": "snmp://192.0.2.10:161",
                    "service": "snmp",
                    "username": "N/A",
                    "password": "private",
                    "_secret_kind": "community",
                }
            )

        validation, credential = (call.args[0] for call in send.call_args_list)
        self.assertEqual("community", validation["secret_kind"])
        self.assertEqual("community", credential["secret_kind"])
        self.assertEqual(validation["credential_ref"], credential["credential_ref"])


if __name__ == "__main__":
    unittest.main()
