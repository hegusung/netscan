import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from utils.credential_campaign import (  # noqa: E402
    CampaignState,
    iter_credential_attempts,
    iter_target_credential_attempts,
)


class CredentialCampaignTests(unittest.TestCase):
    def test_spray_is_secret_major_and_honors_domains_and_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            users = Path(temp_dir) / "users.txt"
            passwords = Path(temp_dir) / "passwords.txt"
            users.write_text("EXAMPLE\\alice\nbob\n", encoding="utf-8")
            passwords.write_text("One!\nTwo!\nThree!\n", encoding="utf-8")
            attempts = list(
                iter_credential_attempts(
                    {"hostname": "192.0.2.1"},
                    users,
                    passwords,
                    default_domain="DEFAULT",
                    strategy="spray",
                    max_attempts_per_account=2,
                )
            )

        self.assertEqual(
            [(a["b_username"], a["b_secret"]) for a in attempts],
            [("alice", "One!"), ("bob", "One!"), ("alice", "Two!"), ("bob", "Two!")],
        )
        self.assertEqual(attempts[0]["b_domain"], "EXAMPLE")
        self.assertEqual(attempts[1]["b_domain"], "DEFAULT")

    def test_state_stops_after_success_and_lockout(self):
        target = {"hostname": "192.0.2.1"}
        state = CampaignState()
        self.assertTrue(state.should_attempt(target, "EXAMPLE", "alice"))
        state.mark_success(target, "EXAMPLE", "alice")
        self.assertFalse(state.should_attempt(target, "EXAMPLE", "alice"))
        state.mark_locked(target, "EXAMPLE", "bob")
        self.assertFalse(state.should_attempt(target, "EXAMPLE", "bob"))

        state.mark_locked(target, None, "local-user")
        self.assertFalse(state.should_attempt(target, None, "local-user"))
        self.assertTrue(
            state.should_attempt({"hostname": "192.0.2.2"}, None, "local-user")
        )

        continuing = CampaignState(continue_on_success=True)
        continuing.mark_success(target, "EXAMPLE", "alice")
        self.assertTrue(continuing.should_attempt(target, "EXAMPLE", "alice"))

    def test_scope_wide_spray_completes_each_secret_round(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            users = Path(temp_dir) / "users.txt"
            passwords = Path(temp_dir) / "passwords.txt"
            users.write_text("alice\nbob\n", encoding="utf-8")
            passwords.write_text("One!\nTwo!\n", encoding="utf-8")
            attempts = list(
                iter_target_credential_attempts(
                    {"targets": "192.0.2.1,192.0.2.2"},
                    {"port": 22},
                    users,
                    passwords,
                    strategy="spray",
                )
            )

        self.assertEqual([item["b_spray_round"] for item in attempts], [0] * 4 + [1] * 4)
        self.assertEqual({item["b_spray_round_size"] for item in attempts}, {4})
        self.assertEqual(
            [item["b_secret"] for item in attempts], ["One!"] * 4 + ["Two!"] * 4
        )

    def test_claim_is_released_when_attempt_completes(self):
        target = {
            "hostname": "192.0.2.1",
            "b_domain": "EXAMPLE",
            "b_username": "alice",
        }
        state = CampaignState()
        self.assertTrue(state.claim_attempt(target, "EXAMPLE", "alice"))
        state.mark_success(target, "EXAMPLE", "alice")
        state.complete_attempt(target)
        self.assertFalse(state.claim_attempt(target, "EXAMPLE", "alice"))


if __name__ == "__main__":
    unittest.main()
