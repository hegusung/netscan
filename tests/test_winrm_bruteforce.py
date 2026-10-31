import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lib.winrmscan.winrm_bruteforce import (  # noqa: E402
    bruteforce_worker,
    bruteforce_generator,
    bruteforce_generator_count,
)
from utils.credential_campaign import CampaignState  # noqa: E402


class WinRMBruteforceTests(unittest.TestCase):
    def test_generator_supports_files_and_inline_passwords(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            users = Path(temp_dir) / "users.txt"
            passwords = Path(temp_dir) / "passwords.txt"
            users.write_text("alice\nbob:Inline!\n", encoding="utf-8")
            passwords.write_text("First!\nSecond!\n", encoding="utf-8")

            target = {"hostname": "192.0.2.10", "port": 5985, "ssl": False}
            generated = list(bruteforce_generator(target, users, passwords))

            self.assertEqual(len(generated), 3)
            self.assertEqual(generated[0]["b_username"], "alice")
            self.assertEqual(generated[0]["b_secret"], "First!")
            self.assertEqual(generated[1]["b_username"], "alice")
            self.assertEqual(generated[1]["b_secret"], "Second!")
            self.assertEqual(generated[2]["b_username"], "bob")
            self.assertEqual(generated[2]["b_secret"], "Inline!")
            self.assertEqual(
                bruteforce_generator_count(target, users, passwords), 3
            )

    def test_simple_mode_uses_username_as_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            users = Path(temp_dir) / "users.txt"
            users.write_text("alice\n", encoding="utf-8")
            target = {"hostname": "192.0.2.10", "port": 5986, "ssl": True}

            generated = list(
                bruteforce_generator(target, users, None, simple_bruteforce=True)
            )
            self.assertEqual(generated[0]["b_secret"], "alice")

    @patch("lib.winrmscan.winrm_bruteforce.Output.event")
    @patch("lib.winrmscan.winrm_bruteforce.DB.insert_credential_validation")
    @patch("lib.winrmscan.winrm_bruteforce.DB.insert_vulnerability")
    @patch("lib.winrmscan.winrm_bruteforce.DB.insert_credential")
    @patch("lib.winrmscan.winrm_bruteforce.DB.insert_port")
    @patch("lib.winrmscan.winrm_bruteforce.WinRMScan")
    def test_successful_attempt_is_persisted(
        self, scanner_type, insert_port, insert_credential, insert_vulnerability,
        insert_validation, success
    ):
        scanner = MagicMock()
        scanner.auth.return_value = True
        scanner.url.return_value = "http://192.0.2.10:5985/wsman"
        scanner_type.return_value = scanner
        target = {
            "hostname": "192.0.2.10",
            "port": 5985,
            "ssl": False,
            "b_domain": "EXAMPLE",
            "b_username": "alice",
            "b_secret": "Secret!",
        }

        bruteforce_worker(target, 5, 0, 0, CampaignState())

        scanner.auth.assert_called_once_with(
            "EXAMPLE", "alice@EXAMPLE", "Secret!", None
        )
        insert_port.assert_called_once()
        insert_credential.assert_called_once()
        insert_vulnerability.assert_called_once()
        insert_validation.assert_called_once()
        success.assert_called_once()
        scanner.disconnect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
