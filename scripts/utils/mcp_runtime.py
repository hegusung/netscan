"""Safe process boundary used by the NetScan MCP server.

This module intentionally has no dependency on the MCP SDK so its validation and
process-management behavior can be tested independently.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

# Every user-facing NetScan command is available. The MCP server itself is not
# included because recursively launching another stdio server is never useful.
# Operators can restrict this list through NETSCAN_MCP_ALLOWED_MODULES.
NETSCAN_MODULES = frozenset(
    {
        "adscan",
        "dnsscan",
        "es_query",
        "ftpscan",
        "generate_payload",
        "httpscan",
        "jdwpscan",
        "mcpscan",
        "mongoscan",
        "mssqlscan",
        "mysqlscan",
        "pingscan",
        "portscan",
        "postgrescan",
        "rdpscan",
        "redisscan",
        "rpcscan",
        "rsh_listener",
        "rsyncscan",
        "rtspscan",
        "server",
        "smbscan",
        "snmpscan",
        "sshscan",
        "telnetscan",
        "tlsscan",
        "vncscan",
        "whoisscan",
        "winrmscan",
    }
)

ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


class MCPRuntimeError(ValueError):
    """Raised when an MCP request violates the configured execution policy."""


@dataclass(frozen=True)
class CommandResult:
    module: str
    exit_code: int
    output: str
    timed_out: bool
    truncated: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "module": self.module,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "output": self.output,
        }


@dataclass(frozen=True)
class PreparedCommand:
    """A validated NetScan subprocess invocation."""

    module: str
    arguments: tuple[str, ...]
    timeout_seconds: int
    command: tuple[str, ...]
    environment: dict[str, str]


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


def allowed_modules() -> tuple[str, ...]:
    configured = os.environ.get("NETSCAN_MCP_ALLOWED_MODULES", "").strip()
    if not configured:
        return tuple(sorted(NETSCAN_MODULES))

    requested = {item.strip() for item in configured.split(",") if item.strip()}
    unknown = requested - NETSCAN_MODULES
    if unknown:
        names = ", ".join(sorted(unknown))
        raise MCPRuntimeError(f"Unknown or disallowed module(s): {names}")
    return tuple(sorted(requested))


def validate_module(module: str) -> str:
    if not isinstance(module, str):
        raise MCPRuntimeError("module must be a string")
    module = module.strip()
    if module not in allowed_modules():
        raise MCPRuntimeError(f"Module '{module}' is not allowed by this MCP server")
    if not (SCRIPTS_DIR / f"{module}.py").is_file():
        raise MCPRuntimeError(f"Module implementation not found: {module}")
    return module


def validate_arguments(arguments: Sequence[str]) -> list[str]:
    if isinstance(arguments, (str, bytes)) or not isinstance(arguments, Sequence):
        raise MCPRuntimeError("arguments must be a list of strings")
    if len(arguments) > 128:
        raise MCPRuntimeError("At most 128 command arguments are allowed")

    validated: list[str] = []
    for argument in arguments:
        if not isinstance(argument, str):
            raise MCPRuntimeError("Every command argument must be a string")
        if "\x00" in argument:
            raise MCPRuntimeError("Command arguments cannot contain NUL bytes")
        if len(argument) > 8192:
            raise MCPRuntimeError("A command argument exceeds the 8192 character limit")
        validated.append(argument)
    return validated


def _positive_env_int(name: str, default: int) -> int:
    raw_value = os.environ.get(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise MCPRuntimeError(f"{name} must be an integer") from exc
    if value <= 0:
        raise MCPRuntimeError(f"{name} must be greater than zero")
    return value


def maximum_timeout() -> int:
    return _positive_env_int("NETSCAN_MCP_MAX_TIMEOUT", 3600)


def maximum_output() -> int:
    return _positive_env_int("NETSCAN_MCP_MAX_OUTPUT", 200_000)


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return

    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:  # pragma: no cover - NetScan primarily targets Linux
            process.terminate()
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:  # pragma: no cover
                process.kill()
        except ProcessLookupError:
            pass


def _capture_bounded_output(
    process: subprocess.Popen[bytes], timeout_seconds: int, output_limit: int
) -> tuple[bytes, bool, bool]:
    """Drain stdout while retaining at most output_limit bytes."""
    captured = bytearray()
    truncated = False

    def drain() -> None:
        nonlocal truncated
        assert process.stdout is not None
        while chunk := process.stdout.read(65_536):
            remaining = output_limit - len(captured)
            if remaining > 0:
                captured.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True

    reader = threading.Thread(target=drain, name="netscan-mcp-output", daemon=True)
    reader.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_process_group(process)
        process.wait()

    reader.join(timeout=5)
    if reader.is_alive():
        # This should only be reachable if a descendant retained the stdout pipe.
        if process.stdout is not None:
            process.stdout.close()
        reader.join(timeout=1)
    elif process.stdout is not None:
        process.stdout.close()
    return bytes(captured), timed_out, truncated


def prepare_module(
    module: str,
    arguments: Sequence[str],
    timeout_seconds: int,
    *,
    require_enabled: bool = True,
) -> PreparedCommand:
    module = validate_module(module)
    validated_arguments = validate_arguments(arguments)

    if require_enabled and not env_flag("NETSCAN_MCP_ENABLE_RUN"):
        raise MCPRuntimeError(
            "Scan execution is disabled. Set NETSCAN_MCP_ENABLE_RUN=true in the "
            "MCP server environment after confirming that targets are authorized."
        )

    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool):
        raise MCPRuntimeError("timeout_seconds must be an integer")
    max_timeout = maximum_timeout()
    if timeout_seconds < 1 or timeout_seconds > max_timeout:
        raise MCPRuntimeError(f"timeout_seconds must be between 1 and {max_timeout}")

    command = [sys.executable, str(SCRIPTS_DIR / f"{module}.py"), *validated_arguments]
    environment = os.environ.copy()
    environment["PYTHONUNBUFFERED"] = "1"

    return PreparedCommand(
        module=module,
        arguments=tuple(validated_arguments),
        timeout_seconds=timeout_seconds,
        command=tuple(command),
        environment=environment,
    )


def run_module(
    module: str,
    arguments: Sequence[str],
    timeout_seconds: int,
    *,
    require_enabled: bool = True,
) -> CommandResult:
    prepared = prepare_module(
        module,
        arguments,
        timeout_seconds,
        require_enabled=require_enabled,
    )

    process = subprocess.Popen(
        prepared.command,
        cwd=PROJECT_ROOT,
        env=prepared.environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=(os.name == "posix"),
    )

    output_limit = maximum_output()
    output, timed_out, truncated = _capture_bounded_output(
        process, timeout_seconds, output_limit
    )

    decoded = output.decode("utf-8", errors="replace")
    decoded = ANSI_ESCAPE.sub("", decoded)
    if truncated:
        decoded += "\n[output truncated by NetScan MCP server]"

    exit_code = process.returncode
    if timed_out and exit_code == 0:
        exit_code = -1

    return CommandResult(
        module=prepared.module,
        exit_code=exit_code,
        output=decoded,
        timed_out=timed_out,
        truncated=truncated,
    )
