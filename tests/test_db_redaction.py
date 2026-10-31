import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from utils.db import REDACTED, redact_command_arguments  # noqa: E402


class DatabaseAuditRedactionTests(unittest.TestCase):
    def test_authentication_material_is_redacted(self):
        arguments = [
            "target", "--pass", "Secret!", "--hash=012345", "--aes-key", "abcdef"
        ]
        self.assertEqual(
            redact_command_arguments(arguments),
            [
                "target", "--pass", REDACTED, f"--hash={REDACTED}",
                "--aes-key", REDACTED,
            ],
        )

    def test_ad_operations_keep_target_and_redact_new_password(self):
        arguments = [
            "dc.example.test",
            "--set-password", "CN=user,DC=example,DC=test", "NewSecret!",
            "--add-computer", "SCAN01$", "ComputerSecret!",
        ]
        redacted = redact_command_arguments(arguments)
        self.assertIn("CN=user,DC=example,DC=test", redacted)
        self.assertIn("SCAN01$", redacted)
        self.assertNotIn("NewSecret!", redacted)
        self.assertNotIn("ComputerSecret!", redacted)


if __name__ == "__main__":
    unittest.main()
