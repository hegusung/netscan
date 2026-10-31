"""Normalized scanner events shared by CLI, MCP, and persistence adapters."""

from __future__ import annotations

from datetime import datetime, timezone
import re
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

SENSITIVE_MESSAGE_PATTERNS = (
    re.compile(r"(?i)(\bcredentials\b\s+)\S+"),
    re.compile(r"(?i)(\bpassword\b\s*(?:=|:|is|was)?\s*)\S+"),
    re.compile(r"(?i)(\b(?:ntlm\s+)?hash\b\s*(?:=|:|is|was)?\s*)\S+"),
    re.compile(r"(?i)(\baes[ -]?key\b\s*(?:=|:|is|was)?\s*)\S+"),
    re.compile(r"(?i)(\b(?:api[ -]?key|token|community|secret)\b\s*(?:=|:|is|was)?\s*)\S+"),
)

DOCUMENT_CATEGORIES = {
    "tool": "scan",
    "ip": "asset",
    "dns": "asset",
    "port": "service",
    "script": "finding",
    "http": "service",
    "content": "content",
    "application": "application",
    "database": "database",
    "cred_password": "credential",
    "cred_hash": "credential",
    "vuln": "vulnerability",
    "secret": "secret",
    "snmp": "credential",
    "domain_password": "credential",
    "domain_hash": "credential",
}

SAFE_DOCUMENT_FIELDS = frozenset(
    {
        "doc_type",
        "session",
        "host",
        "ip",
        "port",
        "protocol",
        "service",
        "url",
        "domain",
        "username",
        "name",
        "database",
        "table",
        "path",
        "share",
        "source",
        "target",
        "query_type",
        "format",
        "tags",
    }
)


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


def redact_sensitive_text(message: str) -> str:
    redacted = message
    for pattern in SENSITIVE_MESSAGE_PATTERNS:
        redacted = pattern.sub(r"\1<redacted>", redacted)
    return redacted


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
        or category in {"authentication", "credential", "secret"}
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
    if sensitive:
        normalized["message"] = redact_sensitive_text(text)
    return normalized


def event_from_document(document: Mapping[str, Any]) -> dict[str, Any] | None:
    """Create a safe normalized event for a document sent to persistence."""
    source = dict(document)
    document_type = str(source.get("doc_type", ""))
    if not document_type:
        return None
    if document_type.startswith("domain_") and document_type not in DOCUMENT_CATEGORIES:
        category = "identity"
    elif document_type.startswith("host_"):
        category = "asset"
    else:
        category = DOCUMENT_CATEGORIES.get(document_type, "finding")
    severity = "high" if category in {"vulnerability", "secret"} else "info"
    if category == "credential":
        severity = "success"
    target = source.get("url") or source.get("host") or source.get("domain")
    label = source.get("name") or source.get("service") or document_type
    data = {
        key: value
        for key, value in source.items()
        if key in SAFE_DOCUMENT_FIELDS and value is not None
    }
    legacy_type = {
        "high": "major",
        "success": "success",
    }.get(severity, "normal")
    return normalize_output_event(
        {
            "type": legacy_type,
            "target": target,
            "message": f"Persisted {document_type}: {label}",
            "event": {
                "category": category,
                "severity": severity,
                "status": "persisted",
                "sensitive": category in {"credential", "secret"},
                "data": data,
            },
        }
    )
