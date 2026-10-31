"""Normalized scanner events shared by CLI, MCP, and persistence adapters."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping


EVENT_SCHEMA_VERSION = 1

TYPE_TO_SEVERITY = {
    "vuln": "high",
    "major": "high",
    "error": "error",
    "success": "success",
    "highlight": "info",
    "minor": "debug",
    "normal": "info",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _infer_category(event_type: str, message: str) -> str:
    lowered = message.lower()
    if event_type == "vuln":
        return "vulnerability"
    if "administrative privileges" in lowered or "you are an admin" in lowered:
        return "privilege"
    if "authentication" in lowered or "credentials" in lowered:
        return "authentication"
    if "executed command" in lowered or lowered.startswith("command '"):
        return "command"
    if "secret" in lowered or "password found" in lowered:
        return "secret"
    if "artifact" in lowered or "written to" in lowered or "saving " in lowered:
        return "artifact"
    return "finding"


def _infer_status(category: str, message: str) -> str | None:
    lowered = message.lower()
    if category == "authentication":
        if "success" in lowered or "successful" in lowered:
            return "success"
        if "failure" in lowered or "failed" in lowered or "denied" in lowered:
            return "failure"
    if category == "privilege":
        return "admin" if "admin" in lowered else "privileged"
    return None


def normalize_output_event(message: Mapping[str, Any]) -> dict[str, Any]:
    """Convert an arbitrary legacy Output message to the stable event envelope."""
    raw = dict(message)
    explicit = raw.get("event") if isinstance(raw.get("event"), Mapping) else {}
    event_type = str(raw.get("type", "normal"))
    text = str(raw.get("message", ""))
    category = str(
        explicit.get("category") or raw.get("category") or _infer_category(event_type, text)
    )
    severity = str(
        explicit.get("severity")
        or raw.get("severity")
        or TYPE_TO_SEVERITY.get(event_type, "info")
    )
    status = explicit.get("status") or raw.get("status") or _infer_status(category, text)
    explicit_data = explicit.get("data")
    raw_data = raw.get("data")
    data = explicit_data if isinstance(explicit_data, Mapping) else raw_data
    if not isinstance(data, Mapping):
        data = {}
    target = explicit.get("target", raw.get("target"))
    sensitive = bool(
        explicit.get("sensitive", raw.get("sensitive", False))
        or any(token in text.lower() for token in (" password ", " hash ", "aes key"))
        or category in {"credential", "secret"}
    )

    normalized = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "category": category,
        "severity": severity,
        "status": status,
        "target": target,
        "message": text,
        "timestamp": str(explicit.get("timestamp") or raw.get("timestamp") or _utc_now()),
        "sensitive": sensitive,
        "data": dict(data),
        "legacy_type": str(raw.get("legacy_type", event_type)),
    }
    return normalized
