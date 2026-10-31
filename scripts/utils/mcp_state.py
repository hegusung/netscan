"""Persistent private state used by the NetScan MCP server."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from utils.mcp_runtime import PROJECT_ROOT


def state_directory() -> Path:
    configured = os.environ.get("NETSCAN_MCP_STATE_DIR", "").strip()
    path = Path(configured).expanduser() if configured else PROJECT_ROOT / ".netscan-mcp"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def atomic_json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, ensure_ascii=False, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
