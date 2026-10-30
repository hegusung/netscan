import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER_PATH = PROJECT_ROOT / "netscan_mcp_server.py"


def load_launcher():
    spec = importlib.util.spec_from_file_location("netscan_root_mcp_launcher", LAUNCHER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class MCPLauncherTests(unittest.TestCase):
    def test_existing_project_venv_is_reexecuted(self):
        launcher = load_launcher()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            python = root / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.touch()
            with (
                patch.object(launcher, "_in_container", return_value=False),
                patch.object(launcher.sys, "executable", "/usr/bin/python3"),
                patch.object(launcher.sys, "argv", ["launcher", "--help"]),
                patch.object(launcher.os, "execv") as execv,
            ):
                launcher._ensure_venv(root)

        execv.assert_called_once_with(
            str(python),
            [str(python), str(LAUNCHER_PATH), "--help"],
        )

    def test_missing_project_venv_is_created_and_dependencies_installed(self):
        launcher = load_launcher()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            expected_python = root / ".venv" / "bin" / "python"
            with (
                patch.object(launcher, "_in_container", return_value=False),
                patch.object(launcher, "_python_312", return_value=Path("/python3.12")),
                patch.object(launcher.subprocess, "check_call") as check_call,
                patch.object(launcher.os, "execv"),
                patch("builtins.print"),
            ):
                launcher._ensure_venv(root)

        self.assertEqual(check_call.call_count, 3)
        self.assertEqual(
            check_call.call_args_list[0].args[0],
            ["/python3.12", "-m", "venv", str(root / ".venv")],
        )
        self.assertEqual(
            check_call.call_args_list[2].args[0],
            [
                str(expected_python),
                "-m",
                "pip",
                "install",
                "-r",
                str(root / "requirements.txt"),
            ],
        )

    def test_container_skips_project_venv(self):
        launcher = load_launcher()
        with (
            patch.object(launcher, "_in_container", return_value=True),
            patch.object(launcher.os, "execv") as execv,
            patch.object(launcher.subprocess, "check_call") as check_call,
        ):
            launcher._ensure_venv(Path("/unused"))
        execv.assert_not_called()
        check_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
