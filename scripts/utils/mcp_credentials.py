"""Opaque, session-scoped access to credentials stored by NetScan."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Literal

from utils.mcp_elasticsearch import _bool_option, _option, _read_config
from utils.mcp_runtime import MCPRuntimeError, PROJECT_ROOT
from utils.mcp_state import state_directory


CREDENTIAL_TYPES = ("cred_password", "cred_hash", "domain_password", "domain_hash")


class CredentialCatalog:
    """Query credentials without returning their authentication material."""

    def __init__(self, *, state_dir: Path | None = None) -> None:
        self.state_dir = state_dir or state_directory()
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        path = self.state_dir / "credential-id.key"
        try:
            value = path.read_bytes()
        except FileNotFoundError:
            value = secrets.token_bytes(32)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            try:
                descriptor = os.open(path, flags, 0o600)
            except FileExistsError:
                value = path.read_bytes()
                if len(value) < 32:
                    raise MCPRuntimeError("The MCP credential ID key is invalid")
                return value
            with os.fdopen(descriptor, "wb") as output:
                output.write(value)
        if len(value) < 32:
            raise MCPRuntimeError("The MCP credential ID key is invalid")
        return value

    def _identifier(self, index: str, document_id: str) -> str:
        digest = hmac.new(
            self._key, f"{index}\0{document_id}".encode(), hashlib.sha256
        ).hexdigest()
        return f"cred_{digest[:32]}"

    def _documents(self, session: str | None = None) -> tuple[str, list[dict[str, Any]]]:
        parser = _read_config(PROJECT_ROOT / "config.cfg")
        if not _bool_option(parser, "Elasticsearch", "enabled", False):
            raise MCPRuntimeError("Elasticsearch is disabled in config.cfg")
        configured_session = _option(parser, "Global", "session", "Unknown")
        selected_session = session or configured_session
        index = _option(parser, "Elasticsearch", "index", "pentest").lower()
        scheme = "https" if _bool_option(parser, "Elasticsearch", "ssl", False) else "http"
        host = _option(parser, "Elasticsearch", "host", "127.0.0.1")
        port = _option(parser, "Elasticsearch", "port", "9200")
        try:
            maximum = min(
                10_000,
                max(1, int(os.environ.get("NETSCAN_MCP_MAX_CREDENTIALS", "5000"))),
            )
        except ValueError as exc:
            raise MCPRuntimeError(
                "NETSCAN_MCP_MAX_CREDENTIALS must be an integer"
            ) from exc
        query = {
            "size": maximum,
            "query": {
                "bool": {
                    "filter": [
                        {"terms": {"doc_type.keyword": list(CREDENTIAL_TYPES)}},
                        {"term": {"session.keyword": selected_session}},
                    ]
                }
            },
        }
        url = f"{scheme}://{host}:{port}/{urllib.parse.quote(index, safe='')}/_search"
        request = urllib.request.Request(
            url,
            data=json.dumps(query).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        username = _option(parser, "Elasticsearch", "username", "")
        if username:
            password = _option(parser, "Elasticsearch", "password", "")
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            request.add_header("Authorization", f"Basic {token}")
        context = None
        if scheme == "https":
            if _bool_option(parser, "Elasticsearch", "verify_certificates", False):
                ca_certs = _option(parser, "Elasticsearch", "ca_certs", "")
                context = ssl.create_default_context(cafile=ca_certs or None)
            else:
                context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, timeout=10, context=context) as response:
                payload = json.load(response)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise MCPRuntimeError(f"Unable to query NetScan credentials: {exc}") from exc
        hits = payload.get("hits", {}).get("hits", [])
        return index, [item for item in hits if isinstance(item, dict)]

    def _entry(self, index: str, hit: dict[str, Any]) -> dict[str, Any] | None:
        source = hit.get("_source")
        if not isinstance(source, dict):
            return None
        document_type = str(source.get("doc_type", ""))
        secret_field = "password" if document_type.endswith("password") else "hash"
        secret = source.get(secret_field)
        username = source.get("username")
        document_id = hit.get("_id")
        if (
            not isinstance(secret, str)
            or not isinstance(username, str)
            or not isinstance(document_id, str)
            or not document_id
        ):
            return None
        identifier = self._identifier(index, document_id)
        return {
            "credential_id": identifier,
            "session": source.get("session"),
            "scope": "domain" if document_type.startswith("domain_") else "host",
            "kind": secret_field,
            "format": source.get("format"),
            "domain": source.get("domain"),
            "username": username,
            "service": source.get("service"),
            "host": source.get("host"),
            "port": source.get("port"),
            "url": source.get("url"),
            "provenance": document_type,
            "_secret": secret,
        }

    @staticmethod
    def _public(entry: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in entry.items() if not key.startswith("_")}

    def list(
        self,
        *,
        session: str | None = None,
        domain: str | None = None,
        service: str | None = None,
        host: str | None = None,
        kind: Literal["password", "hash"] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise MCPRuntimeError("limit must be between 1 and 1000")
        index, hits = self._documents(session)
        entries = [self._entry(index, hit) for hit in hits]
        entries = [entry for entry in entries if entry is not None]
        filters = {"domain": domain, "service": service, "host": host, "kind": kind}
        for field, expected in filters.items():
            if expected is not None:
                entries = [
                    entry
                    for entry in entries
                    if str(entry.get(field) or "").lower() == expected.lower()
                ]
        entries = entries[:limit]
        return {
            "credentials": [self._public(entry) for entry in entries],
            "count": len(entries),
            "secrets_returned": False,
        }

    def resolve(self, credential_id: str, *, session: str | None = None) -> dict[str, Any]:
        index, hits = self._documents(session)
        for hit in hits:
            entry = self._entry(index, hit)
            if entry is not None and hmac.compare_digest(
                entry["credential_id"], credential_id
            ):
                return entry
        raise MCPRuntimeError("Unknown credential_id in the selected NetScan session")
