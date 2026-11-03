"""Read-only, session-scoped Elasticsearch query tools for NetScan MCP."""

from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from utils.mcp_elasticsearch import _bool_option, _option, _read_config
from utils.mcp_runtime import MCPRuntimeError, PROJECT_ROOT


DOCUMENT_TYPES: dict[str, dict[str, Any]] = {
    "tool": {"description": "NetScan command invocation; command line is sensitive", "fields": ["tool", "cmdline"], "sensitive_fields": ["cmdline"]},
    "ip": {"description": "Discovered host", "fields": ["host", "ip", "rtt"]},
    "dns": {"description": "DNS query result", "fields": ["source", "query_type", "target", "ip", "fqdn"]},
    "port": {"description": "Open port and detected service", "fields": ["host", "ip", "port", "protocol", "service", "subservice", "version", "nmap_service", "nmap_version", "banner", "service_info", "tags"]},
    "script": {"description": "Nmap script result", "fields": ["host", "port", "protocol", "nmap_service", "name", "output"]},
    "http": {"description": "HTTP service and response metadata", "fields": ["host", "port", "protocol", "service", "url", "http"]},
    "content": {"description": "Discovered files and directories", "fields": ["url", "path", "share", "service", "account", "size", "access", "type", "directory", "name", "ext"]},
    "application": {"description": "Discovered application", "fields": ["url", "name", "version", "installdate"]},
    "database": {"description": "Discovered database/table", "fields": ["url", "service", "database", "table", "account"]},
    "cred_password": {"description": "Stored service password; sensitive", "fields": ["host", "port", "url", "service", "domain", "username", "password", "secret_kind", "credential_ref"], "sensitive_fields": ["password"]},
    "cred_hash": {"description": "Stored service hash; sensitive", "fields": ["host", "port", "url", "service", "domain", "username", "hash", "format", "secret_kind", "credential_ref"], "sensitive_fields": ["hash"]},
    "credential_validation": {"description": "Secret-free credential validation outcome", "fields": ["host", "port", "url", "service", "domain", "username", "secret_kind", "status", "admin", "source", "credential_ref"]},
    "vuln": {"description": "Vulnerability or security finding", "fields": ["host", "port", "url", "service", "name", "description", "severity", "status"]},
    "secret": {"description": "Secret discovery metadata; line contains matching file content and is sensitive", "fields": ["host", "filepath", "name", "ext", "secret_name", "line", "reliability", "service"], "sensitive_fields": ["line"]},
    "snmp": {"description": "SNMP object/value", "fields": ["host", "port", "snmp_key", "snmp_type", "snmp_value"]},
    "whois_ip": {"description": "WHOIS information for an IP range", "fields": ["ip", "cidr", "name", "country"]},
    "whois_domain": {"description": "WHOIS information for a domain", "fields": ["domain", "registrar", "raw"]},
    "domain": {"description": "Active Directory domain", "fields": ["domain", "parameters", "sid", "dn", "created_date"]},
    "domain_container": {"description": "Active Directory container", "fields": ["domain", "guid", "dn", "name", "description", "created_date"]},
    "domain_ou": {"description": "Active Directory organizational unit", "fields": ["domain", "guid", "dn", "name", "description", "created_date", "gpo"]},
    "domain_gpo": {"description": "GPO metadata, ACLs and parsed effective group changes", "fields": ["domain", "gpo_name", "guid", "dn", "gpcpath", "aces", "owner", "gpo_effect", "description", "created_date"]},
    "domain_gpochange": {"description": "Parsed SYSVOL GPO setting; action/value/command text can contain credentials", "fields": ["domain", "guid", "dn", "gpo_name", "type", "action", "action_display", "name", "value", "file", "target", "arguments", "app", "path", "registry", "section", "property", "group", "members", "firewall_rules", "applocker"], "sensitive_fields": ["action", "action_display", "value", "arguments", "app"]},
    "domain_host": {"description": "Active Directory computer", "fields": ["domain", "hostname", "hostname_ip", "os", "sid", "created_date", "last_logon", "last_logon_timestamp", "last_password_change", "append"]},
    "domain_user": {"description": "Active Directory user", "fields": ["domain", "username", "sid", "dn", "displayname", "enabled", "admincount", "description", "created_date", "last_logon", "last_logon_timestamp", "last_password_change", "append"]},
    "domain_group": {"description": "Active Directory group", "fields": ["domain", "groupname", "sid", "dn", "description", "created_date", "append"]},
    "domain_password": {"description": "Stored domain password; sensitive", "fields": ["domain", "username", "password", "secret_kind", "credential_ref"], "sensitive_fields": ["password"]},
    "domain_hash": {"description": "Stored domain hash; sensitive", "fields": ["domain", "username", "hash", "format", "secret_kind", "credential_ref"], "sensitive_fields": ["hash"]},
    "domain_dns": {"description": "Active Directory DNS entry", "fields": ["domain", "dns"]},
    "domain_ntauthcertificate": {"description": "NTAuth certificate", "fields": ["domain", "name", "created_date"]},
    "domain_rootca": {"description": "Root CA certificate", "fields": ["domain", "name", "created_date"]},
    "domain_aiaca": {"description": "AIA CA certificate", "fields": ["domain", "name", "created_date"]},
    "domain_enrollmentservice": {"description": "Enterprise certificate authority", "fields": ["domain", "name", "created_date"]},
    "domain_certificatetemplate": {"description": "Active Directory certificate template", "fields": ["domain", "name", "created_date", "mspki-certificate-name-flag", "mspki-enrollment-flag", "mspki-ra-signature"]},
    "host_linux": {"description": "Linux host enumeration result", "fields": ["host", "hostname", "os", "kernel", "architecture", "users", "interfaces"]},
    "host_linux_pkg": {"description": "Linux package/version result", "fields": ["host", "pkg_name", "version"]},
}

COMMON_FIELDS = {
    "@timestamp": "Document timestamp (date; epoch milliseconds)",
    "session.keyword": "NetScan engagement/session name; every query is restricted to one exact session",
    "doc_type.keyword": "Document category; see document_types below",
    "host.keyword": "Target IP/host when available",
    "hostname.keyword": "Resolved or reported hostname when available",
    "ip": "Target IP (mapped as Elasticsearch ip)",
    "port": "TCP/UDP port (integer)",
    "protocol.keyword": "Transport protocol, usually tcp or udp",
    "service.keyword": "Detected/application protocol",
    "url.keyword": "Service URL or locator",
    "append.tags.keyword": "NetScan tags appended to the document by the database layer",
}

SENSITIVE_FIELD_NAMES = frozenset(
    {
        "password", "hash", "secret", "secret_value", "token", "api_key",
        "community", "ntlm", "aes_key", "private_key", "authorization",
        "cookie", "set_cookie", "access_token", "refresh_token", "cmdline",
    }
)
SAFE_SECRET_METADATA_FIELDS = frozenset({"secret_kind", "secret_name", "credential_ref"})
SENSITIVE_FIELD_SUFFIXES = (
    "_password", "_hash", "_secret", "_token", "_api_key", "_community",
    "_ntlm", "_aes_key", "_private_key",
)
SAFE_SEARCH_FIELDS = [
    "host", "hostname", "url", "service", "name", "description",
    "message", "domain", "username", "path", "filepath", "gpo_name",
]
NON_KEYWORD_FIELDS = frozenset(
    {
        "@timestamp", "ip", "port", "rtt", "size", "created_date", "last_access",
        "last_modification", "last_logon", "last_logon_timestamp",
        "last_password_change", "geoip_loc",
    }
)
AGGREGATION_RAW_FIELDS = NON_KEYWORD_FIELDS | {"admin", "sensitive"}
FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_@-]+(?:\.[A-Za-z0-9_@-]+)*$")


def elasticsearch_schema() -> dict[str, Any]:
    """Return the query guide used by the MCP resource and schema tool."""
    return {
        "title": "NetScan Elasticsearch document schema",
        "version": 1,
        "configured_index_only": True,
        "session_scoping": "Every search and aggregation requires an exact session filter. If omitted, the configured Global.session is used.",
        "query_model": {
            "filters": "A flat map of field to exact value, or a list of exact values. Strings use the .keyword subfield automatically unless the field is explicitly typed (for example ip, port, or @timestamp).",
            "search_text": "Optional simple text search across host, hostname, url, service, name, description, message, domain, username, path, filepath, and gpo_name.",
            "aggregation": "Terms aggregation on one field; string fields use .keyword automatically. Secret-like fields cannot be aggregated.",
            "pagination": "Search supports size 1..100 and offset 0..10000. Narrow by doc_type and filters for large sessions.",
            "sensitive_data": "Known sensitive field names, secret-file contents, and GPO action/value/command details are redacted by default. Set include_sensitive=true only when the requested analysis needs those values.",
            "field_projection": "Use fields to return only selected source fields. Field names follow the entries below; use nested paths with dots where applicable. geoip_loc is a geo_point and is not supported by exact filters or terms aggregations.",
        },
        "common_fields": COMMON_FIELDS,
        "document_types": DOCUMENT_TYPES,
        "examples": [
            {"tool": "netscan_es_search", "arguments": {"doc_type": "port", "filters": {"service": "ssh"}, "limit": 20}},
            {"tool": "netscan_es_search", "arguments": {"doc_type": "vuln", "search_text": "critical", "fields": ["host", "url", "service", "name", "description"], "limit": 20}},
            {"tool": "netscan_es_aggregate", "arguments": {"doc_type": "port", "field": "service", "size": 20}},
            {"tool": "netscan_es_search", "arguments": {"doc_type": "domain_gpochange", "filters": {"type": "update_environment"}, "fields": ["domain", "gpo_name", "name", "type"], "limit": 50}},
        ],
        "notes": [
            "NetScan creates one configured index and stores many document categories in it, distinguished by doc_type.",
            "Dynamic string fields generally have a .keyword subfield for exact filters and terms aggregations; inspect live index mappings when a custom field behaves differently.",
            "Nested objects such as http, service_info, append, gpo_effect, and applocker depend on the scanner and may vary by record.",
            "Credential documents (cred_password, cred_hash, domain_password, domain_hash) and secret discovery records must be treated as sensitive.",
        ],
    }


def elasticsearch_schema_resource() -> str:
    return json.dumps(elasticsearch_schema(), indent=2, ensure_ascii=False)


def _connection_settings() -> tuple[str, str, str, str, str, str, bool, str]:
    parser = _read_config(PROJECT_ROOT / "config.cfg")
    if not _bool_option(parser, "Elasticsearch", "enabled", False):
        raise MCPRuntimeError("Elasticsearch is disabled in config.cfg")
    scheme = "https" if _bool_option(parser, "Elasticsearch", "ssl", False) else "http"
    host = _option(parser, "Elasticsearch", "host", "127.0.0.1")
    port = _option(parser, "Elasticsearch", "port", "9200")
    index = _option(parser, "Elasticsearch", "index", "pentest").lower()
    if not re.fullmatch(r"[a-z0-9._-]{1,255}", index) or index in {".", ".."}:
        raise MCPRuntimeError("Configured Elasticsearch index name is invalid")
    try:
        if not 1 <= int(port) <= 65535:
            raise ValueError
    except ValueError as exc:
        raise MCPRuntimeError("Configured Elasticsearch port must be between 1 and 65535") from exc
    if (
        not host
        or host != host.strip()
        or "://" in host
        or any(char.isspace() or char in "/?#" for char in host)
    ):
        raise MCPRuntimeError("Configured Elasticsearch host is invalid")
    username = _option(parser, "Elasticsearch", "username", "")
    password = _option(parser, "Elasticsearch", "password", "")
    verify = _bool_option(parser, "Elasticsearch", "verify_certificates", False)
    ca_certs = _option(parser, "Elasticsearch", "ca_certs", "")
    return scheme, host, port, index, username, password, verify, ca_certs


def _request(path: str, body: dict[str, Any]) -> dict[str, Any]:
    scheme, host, port, index, username, password, verify, ca_certs = _connection_settings()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    url = f"{scheme}://{host}:{port}/{urllib.parse.quote(index, safe='')}/{path.lstrip('/')}"
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if username:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
    try:
        context = None
        if scheme == "https":
            context = (
                ssl.create_default_context(cafile=ca_certs or None)
                if verify
                else ssl._create_unverified_context()
            )
        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        raise MCPRuntimeError(f"Elasticsearch returned HTTP {exc.code} for the configured index") from exc
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
        raise MCPRuntimeError(f"Unable to query Elasticsearch: {exc}") from exc
    if not isinstance(result, dict):
        raise MCPRuntimeError("Elasticsearch returned an unexpected response")
    return result


def _selected_session(session: str | None) -> str:
    if session is None:
        parser = _read_config(PROJECT_ROOT / "config.cfg")
        selected = _option(parser, "Global", "session", "Unknown")
    else:
        selected = session.strip()
    if not selected or selected.lower() == "unknown":
        raise MCPRuntimeError("Set Global.session in config.cfg or pass an explicit session")
    if len(selected) > 256:
        raise MCPRuntimeError("Session name exceeds 256 characters")
    return selected


def _exact_field(field: str, value: Any) -> str:
    if len(field) > 255 or not FIELD_NAME_RE.fullmatch(field):
        raise MCPRuntimeError(f"Invalid Elasticsearch field name: {field!r}")
    if field == "geoip_loc":
        raise MCPRuntimeError("geoip_loc requires a geo query, which this tool does not expose")
    if field.endswith(".keyword") or field in NON_KEYWORD_FIELDS:
        return field
    if isinstance(value, str) or (
        isinstance(value, list) and any(isinstance(item, str) for item in value)
    ):
        return field + ".keyword"
    return field


def _build_query(
    *, session: str | None, doc_type: str | None, filters: dict[str, Any] | None,
    search_text: str | None = None,
) -> tuple[str, dict[str, Any]]:
    selected_session = _selected_session(session)
    clauses: list[dict[str, Any]] = [
        {"term": {"session.keyword": selected_session}},
    ]
    if doc_type is not None:
        if doc_type not in DOCUMENT_TYPES:
            raise MCPRuntimeError(f"Unknown NetScan document type: {doc_type}")
        clauses.append({"term": {"doc_type.keyword": doc_type}})
    if filters:
        if len(filters) > 30:
            raise MCPRuntimeError("At most 30 exact filters are allowed")
        for field, value in filters.items():
            if value is None or isinstance(value, dict):
                raise MCPRuntimeError("Filters must map field names to scalar values or scalar lists")
            values = value if isinstance(value, list) else [value]
            if not values or len(values) > 100:
                raise MCPRuntimeError("Each filter must contain between 1 and 100 values")
            if any(not isinstance(item, (str, int, float, bool)) for item in values):
                raise MCPRuntimeError("Filter values must be strings, numbers, or booleans")
            if any(isinstance(item, str) and len(item) > 4096 for item in values):
                raise MCPRuntimeError("Filter string exceeds 4096 characters")
            exact_field = _exact_field(field, values[0] if len(values) == 1 else values)
            if len(values) == 1:
                clauses.append({"term": {exact_field: values[0]}})
            else:
                clauses.append({"terms": {exact_field: values}})
    query: dict[str, Any] = {"bool": {"filter": clauses}}
    if search_text:
        text = search_text.strip()
        if len(text) > 512:
            raise MCPRuntimeError("search_text exceeds 512 characters")
        if text:
            query["bool"]["must"] = [{
                "simple_query_string": {
                    "query": text,
                    "fields": SAFE_SEARCH_FIELDS,
                    "default_operator": "and",
                }
            }]
    return selected_session, query


def _is_sensitive_field(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    if normalized in SAFE_SECRET_METADATA_FIELDS:
        return False
    return normalized in SENSITIVE_FIELD_NAMES or normalized.endswith(SENSITIVE_FIELD_SUFFIXES)


def _redact(value: Any, *, doc_type: str, include_sensitive: bool, key: str = "") -> Any:
    if include_sensitive:
        return value
    if _is_sensitive_field(key):
        return "<redacted>"
    if doc_type == "secret" and key == "line":
        return "<redacted; set include_sensitive=true to retrieve>"
    if doc_type == "domain_gpochange" and key in {
        "action", "action_display", "value", "arguments", "app"
    }:
        return "<redacted; set include_sensitive=true to retrieve>"
    if isinstance(value, dict):
        return {item_key: _redact(item, doc_type=doc_type, include_sensitive=False, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, doc_type=doc_type, include_sensitive=False, key=key) for item in value]
    return value


def search_documents(
    *, session: str | None = None, doc_type: str | None = None,
    filters: dict[str, Any] | None = None, search_text: str | None = None,
    fields: list[str] | None = None, limit: int = 20, offset: int = 0,
    include_sensitive: bool = False,
) -> dict[str, Any]:
    if not 1 <= limit <= 100:
        raise MCPRuntimeError("limit must be between 1 and 100")
    if not 0 <= offset or offset + limit > 10_000:
        raise MCPRuntimeError("offset plus limit must not exceed Elasticsearch's 10000-result window")
    includes: list[str] | None = None
    if fields is not None:
        if not 1 <= len(fields) <= 50:
            raise MCPRuntimeError("fields must contain between 1 and 50 field names")
        if any(len(field) > 255 or not FIELD_NAME_RE.fullmatch(field) for field in fields):
            raise MCPRuntimeError("fields contains an invalid field name")
        # Keep doc_type in the payload so type-specific redaction also applies
        # when the caller projects only selected source fields.
        includes = list(dict.fromkeys(["doc_type", *fields]))
    selected_session, query = _build_query(
        session=session, doc_type=doc_type, filters=filters, search_text=search_text
    )
    body: dict[str, Any] = {
        "query": query,
        "size": limit,
        "from": offset,
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }
    if includes is not None:
        body["_source"] = {"includes": includes}
    result = _request("_search", body)
    hits_block = result.get("hits", {})
    total_block = hits_block.get("total", 0)
    total = total_block.get("value", 0) if isinstance(total_block, dict) else total_block
    hits = []
    for hit in hits_block.get("hits", []):
        source = hit.get("_source", {})
        hit_type = str(source.get("doc_type", doc_type or ""))
        hits.append({
            "id": hit.get("_id"),
            "score": hit.get("_score"),
            "source": _redact(source, doc_type=hit_type, include_sensitive=include_sensitive),
        })
    return {
        "index": _connection_settings()[3],
        "session": selected_session,
        "doc_type": doc_type,
        "total": int(total),
        "offset": offset,
        "limit": limit,
        "returned": len(hits),
        "hits": hits,
        "sensitive_fields_included": include_sensitive,
    }


def aggregate_documents(
    *, field: str, session: str | None = None, doc_type: str | None = None,
    filters: dict[str, Any] | None = None, size: int = 20,
) -> dict[str, Any]:
    if not 1 <= size <= 100:
        raise MCPRuntimeError("size must be between 1 and 100")
    if _is_sensitive_field(field):
        raise MCPRuntimeError("Aggregations over sensitive fields are not allowed")
    if field == "geoip_loc":
        raise MCPRuntimeError("Terms aggregations over geoip_loc are not supported")
    selected_session, query = _build_query(
        session=session, doc_type=doc_type, filters=filters
    )
    if len(field) > 255 or not FIELD_NAME_RE.fullmatch(field):
        raise MCPRuntimeError(f"Invalid Elasticsearch field name: {field!r}")
    aggregation_field = (
        field if field.endswith(".keyword") or field in AGGREGATION_RAW_FIELDS
        else field + ".keyword"
    )
    result = _request("_search", {
        "size": 0,
        "track_total_hits": True,
        "query": query,
        "aggs": {
            "values": {
                "terms": {
                    "field": aggregation_field,
                    "size": size,
                    "order": {"_count": "desc"},
                }
            }
        },
    })
    total_block = result.get("hits", {}).get("total", 0)
    total = total_block.get("value", 0) if isinstance(total_block, dict) else total_block
    buckets = result.get("aggregations", {}).get("values", {}).get("buckets", [])
    return {
        "index": _connection_settings()[3],
        "session": selected_session,
        "doc_type": doc_type,
        "field": aggregation_field,
        "matching_documents": int(total),
        "buckets": [{"value": item.get("key"), "count": item.get("doc_count", 0)} for item in buckets],
    }
