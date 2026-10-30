#!/usr/bin/env python3
"""Launch the NetScan MCP server from the repository root."""

from __future__ import annotations

import os
import runpy
import shutil
import subprocess
import sys
from pathlib import Path


def _in_container() -> bool:
    if Path("/.dockerenv").is_file() or Path("/run/.containerenv").is_file():
        return True
    try:
        cgroups = Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return any(
        marker in cgroups
        for marker in ("docker", "containerd", "kubepods", "libpod")
    )


def _python_312() -> Path:
    pyenv = shutil.which("pyenv")
    if pyenv:
        result = subprocess.run(
            [pyenv, "prefix", "3.12"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            candidate = Path(result.stdout.strip()) / "bin" / "python3.12"
            if candidate.is_file():
                return candidate

    system_python = shutil.which("python3.12")
    if system_python:
        return Path(system_python)
    if sys.version_info[:2] == (3, 12):
        return Path(sys.executable)
    raise SystemExit(
        "NetScan MCP requires Python 3.12, but python3.12 was not found "
        "through pyenv or the system PATH."
    )


def _ensure_venv(project_root: Path) -> None:
    if _in_container() or os.environ.get("DISABLE_VENV") == "1":
        return

    venv_dir = project_root / ".venv"
    venv_python = venv_dir / "bin" / "python"
    if not venv_python.is_file():
        bootstrap_python = _python_312()
        print(f"[NetScan MCP] Creating virtual environment in {venv_dir}", file=sys.stderr)
        subprocess.check_call(
            [str(bootstrap_python), "-m", "venv", str(venv_dir)],
            stdout=sys.stderr,
            stderr=sys.stderr,
        )
        subprocess.check_call(
            [str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "wheel"],
            stdout=sys.stderr,
            stderr=sys.stderr,
        )
        subprocess.check_call(
            [
                str(venv_python),
                "-m",
                "pip",
                "install",
                "-r",
                str(project_root / "requirements.txt"),
            ],
            stdout=sys.stderr,
            stderr=sys.stderr,
        )

    if Path(sys.executable).resolve() != venv_python.resolve():
        os.execv(
            str(venv_python),
            [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]],
        )


def main() -> None:
    project_root = Path(__file__).resolve().parent
    _ensure_venv(project_root)
    scripts_dir = project_root / "scripts"
    os.environ.setdefault("NETSCAN_MCP_ENABLE_RUN", "true")
    sys.path.insert(0, str(scripts_dir))
    runpy.run_path(str(scripts_dir / "netscan_mcp_server.py"), run_name="__main__")


if __name__ == "__main__":
    main()
