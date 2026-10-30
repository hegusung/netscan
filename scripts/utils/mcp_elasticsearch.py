"""Credential-safe Elasticsearch context for NetScan MCP clients."""

from __future__ import annotations

import base64
import configparser
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from utils.mcp_runtime import PROJECT_ROOT


def _read_config(config_path: Path | None = None) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(config_path or PROJECT_ROOT / "config.cfg")
    return parser


def _option(
    parser: configparser.ConfigParser, section: str, option: str, default: str
) -> str:
    return parser.get(section, option, fallback=default).strip()


def _bool_option(
    parser: configparser.ConfigParser, section: str, option: str, default: bool
) -> bool:
    value = _option(parser, section, option, str(default))
    return value.lower() in {"1", "true", "yes", "on"}


def _connection_status(
    url: str,
    username: str,
    password: str,
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    if username:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
    context = ssl._create_unverified_context() if url.startswith("https://") else None
    started = time.monotonic()
    try:
        with urllib.request.urlopen(
            request, timeout=timeout_seconds, context=context
        ) as response:
            status = response.status
        return {
            "checked": True,
            "reachable": 200 <= status < 500,
            "http_status": status,
            "authenticated": 200 <= status < 400,
            "latency_ms": round((time.monotonic() - started) * 1000),
        }
    except urllib.error.HTTPError as exc:
        return {
            "checked": True,
            "reachable": True,
            "http_status": exc.code,
            "authenticated": exc.code not in (401, 403),
            "latency_ms": round((time.monotonic() - started) * 1000),
        }
    except (OSError, urllib.error.URLError) as exc:
        return {
            "checked": True,
            "reachable": False,
            "error": str(exc),
            "latency_ms": round((time.monotonic() - started) * 1000),
        }


def elasticsearch_context(
    *,
    check_connection: bool = False,
    timeout_seconds: float = 2.0,
    config_path: Path | None = None,
) -> dict[str, Any]:
    """Return analysis handoff metadata without returning authentication secrets."""
    path = config_path or PROJECT_ROOT / "config.cfg"
    parser = _read_config(path)
    enabled = _bool_option(parser, "Elasticsearch", "enabled", False)
    scheme = (
        "https"
        if _bool_option(parser, "Elasticsearch", "ssl", False)
        else "http"
    )
    host = _option(parser, "Elasticsearch", "host", "127.0.0.1")
    port = _option(parser, "Elasticsearch", "port", "9200")
    index = _option(parser, "Elasticsearch", "index", "pentest").lower()
    session = _option(parser, "Global", "session", "Unknown")
    mcp_url = os.environ.get("NETSCAN_ELASTIC_MCP_URL", "").strip() or _option(
        parser, "Elasticsearch", "mcp_url", ""
    )
    context: dict[str, Any] = {
        "config_present": path.is_file(),
        "enabled": enabled,
        "endpoint": f"{scheme}://{host}:{port}",
        "index": index,
        "session": session,
        "file_storage_enabled": _bool_option(
            parser, "Elasticsearch", "enable_file_storage", False
        ),
        "credentials_configured": bool(
            _option(parser, "Elasticsearch", "username", "")
        ),
        "connection": {"checked": False},
        "analysis_handoff": {
            "preferred_server": "Elastic Agent Builder MCP",
            "mcp_url": mcp_url or None,
            "required_scope": {"index": index, "session": session},
            "instructions": (
                "Inspect the index mapping, then constrain every search, aggregation, "
                "or ES|QL query to this exact NetScan session. Use a read-only identity."
            ),
        },
    }
    if check_connection:
        context["connection"] = _connection_status(
            context["endpoint"],
            _option(parser, "Elasticsearch", "username", ""),
            _option(parser, "Elasticsearch", "password", ""),
            timeout_seconds=timeout_seconds,
        )
    return context
