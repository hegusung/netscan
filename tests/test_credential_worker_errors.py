import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lib.redisscan import redis_bruteforce  # noqa: E402
from lib.smbscan import smb_bruteforce  # noqa: E402
from lib.vncscan import vnc_bruteforce  # noqa: E402


class CredentialWorkerErrorTests(unittest.TestCase):
    def setUp(self):
        self.target = {
            "hostname": "192.0.2.1",
            "port": 1,
            "b_domain": None,
            "b_username": "alice",
            "b_secret": "secret",
        }
        self.state = Mock()
        self.state.claim_attempt.return_value = True

    def test_redis_transport_error_is_persisted(self):
        scanner = Mock()
        scanner.auth.side_effect = ConnectionError("closed")
        scanner.url.return_value = "redis://192.0.2.1:1"
        with (
            patch.object(redis_bruteforce, "Redis", return_value=scanner),
            patch.object(redis_bruteforce, "record_credential_validation") as record,
        ):
            redis_bruteforce.bruteforce_worker(
                self.target, 1, 0, 0, self.state
            )

        self.assertEqual("error", record.call_args.kwargs["status"])
        self.state.complete_attempt.assert_called_once_with(self.target)

    def test_vnc_transport_error_is_persisted(self):
        scanner = Mock()
        scanner.connect.side_effect = ConnectionRefusedError("closed")
        scanner.url.return_value = "vnc://192.0.2.1:1"
        with (
            patch.object(vnc_bruteforce, "VNC", return_value=scanner),
            patch.object(vnc_bruteforce, "record_credential_validation") as record,
        ):
            vnc_bruteforce.bruteforce_worker(
                self.target, 1, 0, 0, self.state
            )

        self.assertEqual("error", record.call_args.kwargs["status"])
        self.state.complete_attempt.assert_called_once_with(self.target)

    def test_smb_connection_error_is_persisted(self):
        scanner = Mock()
        scanner.connect.return_value = False
        scanner.url.return_value = "smb://192.0.2.1:1"
        with (
            patch.object(smb_bruteforce, "SMBScan", return_value=scanner),
            patch.object(smb_bruteforce, "record_credential_validation") as record,
            patch.object(smb_bruteforce.Output, "write"),
        ):
            smb_bruteforce.bruteforce_worker(
                self.target, 0, 0, 1, self.state
            )

        self.assertEqual("error", record.call_args.kwargs["status"])
        self.state.complete_attempt.assert_called_once_with(self.target)


if __name__ == "__main__":
    unittest.main()
