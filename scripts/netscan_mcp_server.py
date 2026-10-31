#!/usr/bin/env python3
"""MCP server exposing authorized NetScan scanner subprocesses."""

from __future__ import annotations

import argparse
import inspect
from typing import Annotated, Any, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from utils.argparse_schema import (
    ArgumentSchemaError,
    ArgumentSpec,
    ModuleSpec,
    extract_argument_specs,
    extract_module_specs,
    values_to_argv,
)
from utils.mcp_runtime import (
    MCPRuntimeError,
    PROJECT_ROOT,
    allowed_modules,
    env_flag,
    maximum_output,
    maximum_timeout,
    run_module,
)
from utils.mcp_elasticsearch import elasticsearch_context
from utils.mcp_credentials import CredentialCatalog
from utils.mcp_jobs import ScanJobManager


JOB_MANAGER = ScanJobManager()
CREDENTIAL_CATALOG = CredentialCatalog()

CREDENTIAL_REUSE_MODULES = (
    "adscan", "ftpscan", "mongoscan", "mssqlscan", "mysqlscan",
    "postgrescan", "rdpscan", "redisscan", "smbscan", "snmpscan",
    "sshscan", "telnetscan", "vncscan", "winrmscan",
)
CredentialModule = Literal[
    "adscan", "ftpscan", "mongoscan", "mssqlscan", "mysqlscan",
    "postgrescan", "rdpscan", "redisscan", "smbscan", "snmpscan",
    "sshscan", "telnetscan", "vncscan", "winrmscan",
]
USERNAME_CREDENTIAL_MODULES = frozenset(
    CREDENTIAL_REUSE_MODULES
) - {"redisscan", "snmpscan", "vncscan"}
DOMAIN_CREDENTIAL_MODULES = frozenset(
    {"adscan", "mssqlscan", "rdpscan", "smbscan", "winrmscan"}
)
HASH_CREDENTIAL_MODULES = DOMAIN_CREDENTIAL_MODULES


mcp = MCPServer(
    "netscan",
    instructions=(
        "Run NetScan only against systems for which the operator has explicit authorization. "
        "Prefer the strongly typed netscan_<module> tools. Call netscan_status and "
        "netscan_context first, and inspect module help when needed. Scanner tools enqueue "
        "background jobs: retain the returned scan_id, poll netscan_scan_status, then call "
        "netscan_scan_result. run_netscan is an argv-style fallback for CLI "
        "features that cannot be represented by a typed tool. Do not infer that a capability "
        "is absent from the lack of a same-named top-level command: inspect the relevant typed "
        "tool and its native help. In particular, NFS discovery, exports, and recursive listing "
        "are provided by netscan_rpcscan; Windows WMI execution is provided by "
        "netscan_smbscan with exec_method=wmiexec, while SMB scan actions also enumerate "
        "processes through WMI and applications through remote Windows commands. NetScan can "
        "validate SMB administrative access, validate the MSSQL sysadmin role, execute Windows "
        "commands, PowerShell, or payloads over SMB, and perform multi-host credential testing "
        "with username/password or NTLM files on supported protocols. FTP, MongoDB, MSSQL, "
        "MySQL, PostgreSQL, RDP, Redis, SMB, SNMP, SSH, Telnet, VNC, and WinRM share a "
        "scope-wide credential campaign engine. Use spray=true for secret-major scheduling "
        "across every target, spray_round_delay and credential_jitter to pace attempts, and "
        "max_attempts_per_account to enforce an account budget. Campaigns stop after a success "
        "and suppress locked accounts unless explicitly configured otherwise. Respect the "
        "operator's lockout policy and authorization. Every campaign attempt is persisted as a "
        "secret-free credential_validation document with target, protocol, result, correlation "
        "reference, and observed administrative privilege. NetScan's database is the configured, "
        "session-scoped Elasticsearch index. It persists scan invocations, services, findings, "
        "credentials, hashes, secrets, AD objects, and discovered admin relationships. "
        "NetScan also has an AD-to-BloodHound workflow: collect domains, containers/OUs, users, "
        "groups, hosts, GPOs and optionally ADCS data with netscan_adscan; enrich host relations "
        "with SMB admins/logged-in users/sessions where required; then call netscan_es_query "
        "with export_bloodhound and the exact session. The export includes domains, containers, "
        "OUs, users, groups, computers, GPOs, and ADCS entities. Do not use nodb during any "
        "collection intended for correlation or export. NetScan is the collection layer; when "
        "a Kibana Agent Builder MCP server is available, use it as the preferred analysis layer for "
        "persisted results. Before querying, inspect the index mappings and identify the active "
        "NetScan session. Scope every analysis query to that session so separate engagements "
        "are never mixed. Treat credentials, hashes, secrets, and recorded command lines as "
        "sensitive: retrieve and disclose them only when explicitly required. Prefer a read-only "
        "Kibana/Elasticsearch identity restricted to the configured NetScan index. If Kibana "
        "MCP is unavailable, or a NetScan-specific export is required, use netscan_es_query "
        "cautiously; it includes destructive operations such as delete_session. Export paths "
        "from netscan_es_query are confined to the job: after completion call "
        "netscan_scan_artifacts and read the returned resource URIs. Scan findings use a stable "
        "versioned event envelope with category, severity, status, target, timestamp, sensitive, "
        "and data fields; prefer those fields over parsing terminal output."
        " Use netscan_credentials to discover opaque IDs for credentials already stored in the "
        "selected Elasticsearch session, then netscan_run_with_credential to reuse one without "
        "requesting or disclosing its password or hash. For an explicitly selected set, use "
        "netscan_run_with_credentials and track each returned scan_id independently."
    ),
)


@mcp.tool()
async def netscan_status() -> dict[str, object]:
    """Return server policy, configuration status, and available scanner modules."""
    config_path = PROJECT_ROOT / "config.cfg"
    return {
        "project_root": str(PROJECT_ROOT),
        "config_file": str(config_path),
        "config_present": config_path.is_file(),
        "scan_execution_enabled": env_flag("NETSCAN_MCP_ENABLE_RUN"),
        "allowed_modules": list(allowed_modules()),
        "typed_tools": [f"netscan_{module}" for module in allowed_modules()],
        "maximum_timeout_seconds": maximum_timeout(),
        "maximum_output_bytes": maximum_output(),
        "maximum_concurrent_jobs": JOB_MANAGER.max_workers,
        "retained_jobs": JOB_MANAGER.retention,
        "maximum_artifact_bytes": JOB_MANAGER.artifact_file_limit,
        "maximum_artifact_total_bytes": JOB_MANAGER.artifact_total_limit,
        "persistent_state_directory": str(JOB_MANAGER.state_dir),
        "credential_reuse_modules": list(CREDENTIAL_REUSE_MODULES),
    }


@mcp.tool()
async def netscan_context(check_elasticsearch: bool = True) -> dict[str, object]:
    """Return the active NetScan session and safe Elasticsearch analysis handoff.

    Credentials are never returned. When requested, the connection check uses the
    configured credentials only inside the server process.
    """
    return elasticsearch_context(check_connection=check_elasticsearch)


@mcp.tool()
async def netscan_credentials(
    session: str | None = None,
    domain: str | None = None,
    service: str | None = None,
    host: str | None = None,
    kind: Literal["password", "hash", "community"] | None = None,
    limit: Annotated[int, Field(ge=1, le=1000)] = 100,
) -> dict[str, object]:
    """List opaque IDs and non-secret metadata for persisted NetScan credentials."""
    try:
        return CREDENTIAL_CATALOG.list(
            session=session,
            domain=domain,
            service=service,
            host=host,
            kind=kind,
            limit=limit,
        )
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc


def _validate_credential_arguments(module: str, arguments: list[str]) -> None:
    forbidden = {
        "-u", "--pass", "--hash", "--key", "-c", "--community",
        "-U", "-P", "-C", "--ntlm-file"
    }
    if module in DOMAIN_CREDENTIAL_MODULES:
        forbidden.add("-d")
    if any(item.split("=", 1)[0] in forbidden for item in arguments):
        raise MCPRuntimeError(
            "Authentication arguments cannot be combined with credential_id"
        )


def _start_credential_job(
    module: str,
    targets: str,
    credential: dict[str, Any],
    credential_id: str,
    arguments: list[str],
    timeout_seconds: int,
) -> dict[str, Any]:
    if credential["kind"] == "hash" and module not in HASH_CREDENTIAL_MODULES:
        raise MCPRuntimeError(f"{module} credential reuse requires a password")
    if credential["kind"] == "community" and module != "snmpscan":
        raise MCPRuntimeError("SNMP communities can only be reused with snmpscan")
    native_arguments = [targets]
    if module in USERNAME_CREDENTIAL_MODULES:
        native_arguments.extend(["-u", str(credential["username"])])
    if module in DOMAIN_CREDENTIAL_MODULES and credential.get("domain"):
        native_arguments.extend(["-d", str(credential["domain"])])
    native_arguments.extend(arguments)
    if module == "snmpscan":
        secret_name = "NETSCAN_MCP_CREDENTIAL_COMMUNITY"
    elif credential["kind"] == "password":
        secret_name = "NETSCAN_MCP_CREDENTIAL_PASSWORD"
    else:
        secret_name = "NETSCAN_MCP_CREDENTIAL_HASH"
    credential_context = {
        "credential_id": credential_id,
        "session": credential.get("session"),
        "kind": credential.get("kind"),
        "username": credential.get("username"),
        "provenance": credential.get("provenance"),
        "secret_disclosed": False,
    }
    result = JOB_MANAGER.start(
        module,
        native_arguments,
        timeout_seconds,
        secret_environment={secret_name: str(credential["_secret"])},
        context={"credential": credential_context},
    )
    result["credential"] = credential_context
    return result


@mcp.tool()
async def netscan_run_with_credential(
    module: CredentialModule,
    targets: str,
    credential_id: str,
    arguments: list[str] | None = None,
    session: str | None = None,
    timeout_seconds: Annotated[int, Field(ge=1, le=maximum_timeout())] = 300,
) -> dict[str, object]:
    """Start a scan with a stored credential while keeping its secret server-side."""
    arguments = list(arguments or [])
    try:
        _validate_credential_arguments(module, arguments)
        credential = CREDENTIAL_CATALOG.resolve(credential_id, session=session)
        return _start_credential_job(
            module, targets, credential, credential_id, arguments, timeout_seconds
        )
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool()
async def netscan_run_with_credentials(
    module: CredentialModule,
    targets: str,
    credential_ids: Annotated[list[str], Field(min_length=1, max_length=100)],
    arguments: list[str] | None = None,
    session: str | None = None,
    timeout_seconds: Annotated[int, Field(ge=1, le=maximum_timeout())] = 300,
) -> dict[str, object]:
    """Start one bounded, traceable scan job per stored credential ID."""
    arguments = list(arguments or [])
    try:
        _validate_credential_arguments(module, arguments)
        resolved = [
            (credential_id, CREDENTIAL_CATALOG.resolve(credential_id, session=session))
            for credential_id in credential_ids
        ]
        if module not in HASH_CREDENTIAL_MODULES and any(
            credential["kind"] == "hash" for _, credential in resolved
        ):
            raise MCPRuntimeError(f"{module} credential reuse requires passwords")
        if module != "snmpscan" and any(
            credential["kind"] == "community" for _, credential in resolved
        ):
            raise MCPRuntimeError("SNMP communities can only be reused with snmpscan")
        jobs = [
            _start_credential_job(
                module,
                targets,
                credential,
                credential_id,
                arguments,
                timeout_seconds,
            )
            for credential_id, credential in resolved
        ]
        return {"jobs": jobs, "count": len(jobs), "secrets_disclosed": False}
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool()
async def netscan_list_scans(
    state: Literal[
        "queued", "running", "succeeded", "failed", "cancelled", "timed_out"
    ]
    | None = None,
    limit: Annotated[int, Field(ge=1, le=100)] = 20,
) -> dict[str, object]:
    """List recent background scans, optionally restricted to one state."""
    try:
        scans = JOB_MANAGER.list(state=state, limit=limit)
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc
    return {"scans": scans, "count": len(scans)}


@mcp.tool()
async def netscan_scan_status(scan_id: str) -> dict[str, object]:
    """Return lifecycle and output progress for one background scan."""
    try:
        return JOB_MANAGER.status(scan_id)
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool()
async def netscan_cancel_scan(scan_id: str) -> dict[str, object]:
    """Cancel a queued or running scan and terminate its subprocess group."""
    try:
        return JOB_MANAGER.cancel(scan_id)
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool()
async def netscan_scan_result(
    scan_id: str, include_findings: bool = True
) -> dict[str, object]:
    """Return a scan summary, structured findings, and Elasticsearch handoff."""
    try:
        return JOB_MANAGER.result(scan_id, include_findings=include_findings)
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool()
async def netscan_scan_output(
    scan_id: str,
    offset: Annotated[int, Field(ge=0)] = 0,
    limit: Annotated[int, Field(ge=1, le=100_000)] = 20_000,
) -> dict[str, object]:
    """Read a bounded page of captured scanner output."""
    try:
        return JOB_MANAGER.output_chunk(scan_id, offset, limit)
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool()
async def netscan_scan_artifacts(scan_id: str) -> dict[str, object]:
    """List files produced by a scan and their confined MCP resource URIs."""
    try:
        return JOB_MANAGER.list_artifacts(scan_id)
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc


@mcp.resource("netscan://scans/{scan_id}/output", mime_type="text/plain")
async def netscan_scan_output_resource(scan_id: str) -> str:
    """Captured output for a background NetScan job."""
    try:
        return JOB_MANAGER.output_text(scan_id)
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc


@mcp.resource(
    "netscan://scans/{scan_id}/artifacts/{artifact_id}",
    mime_type="application/octet-stream",
)
async def netscan_scan_artifact_resource(scan_id: str, artifact_id: str) -> bytes:
    """A file produced inside the confined artifact directory of a scan job."""
    try:
        return JOB_MANAGER.artifact_bytes(scan_id, artifact_id)
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool()
async def netscan_module_help(module: str) -> dict[str, object]:
    """Return the native command-line help for an allowed NetScan module."""
    try:
        result = run_module(
            module,
            ["--help"],
            30,
            require_enabled=False,
        )
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc
    return result.as_dict()


@mcp.tool()
async def run_netscan(
    module: str,
    arguments: list[str],
    timeout_seconds: int = 300,
) -> dict[str, object]:
    """Start an allowed NetScan scanner as a background job.

    Scan execution must be enabled by the server operator with
    NETSCAN_MCP_ENABLE_RUN=true. No shell is used. The caller is responsible for
    ensuring every target and requested action is explicitly authorized.
    """
    try:
        result = JOB_MANAGER.start(module, arguments, timeout_seconds)
    except MCPRuntimeError as exc:
        raise ToolError(str(exc)) from exc
    return result


def _argument_type(spec: ArgumentSpec, modules: tuple[ModuleSpec, ...]) -> Any:
    field_options: dict[str, Any] = {"description": spec.description}
    if spec.dest == "modules" and modules:
        module_choice = Literal.__getitem__(tuple(module.name for module in modules))
        base_type: Any = list[module_choice]
        field_options["min_length"] = 1
        catalog = "; ".join(
            f"{module.name}: {module.description}" for module in modules
        )
        field_options["description"] = (
            f"Select one or more modules. Available modules: {catalog}"
        )
    elif spec.action in ("store_true", "store_false"):
        base_type: Any = bool
    elif spec.value_type == "int":
        base_type = int
    elif spec.value_type == "float":
        base_type = float
    elif spec.value_type == "str_ports":
        base_type = list[int]
    elif spec.value_type == "str_comma":
        base_type = list[str]
    elif spec.value_type == "top_ports":
        base_type = int
    else:
        base_type = str

    if (
        spec.dest != "modules"
        and spec.takes_many
        and spec.value_type not in ("str_ports", "str_comma")
    ):
        base_type = list[base_type]
        if spec.nargs == "+":
            field_options["min_length"] = 1
        elif isinstance(spec.nargs, int):
            field_options["min_length"] = spec.nargs
            field_options["max_length"] = spec.nargs
    elif spec.value_type in ("str_ports", "str_comma"):
        field_options["min_length"] = 1
    if spec.choices and spec.dest != "modules":
        base_type = Literal.__getitem__(spec.choices)
        if spec.takes_many:
            base_type = list[base_type]
    if not spec.required:
        base_type = base_type | None
    return Annotated[base_type, Field(**field_options)]


def _make_typed_tool(
    module: str,
    specs: tuple[ArgumentSpec, ...],
    modules: tuple[ModuleSpec, ...],
):
    async def typed_tool(**values: Any) -> dict[str, object]:
        mcp_timeout_seconds = values.pop("mcp_timeout_seconds", 300)
        module_args = values.pop("module_args", None)
        try:
            arguments = values_to_argv(specs, values, module_args=module_args)
            result = JOB_MANAGER.start(module, arguments, mcp_timeout_seconds)
        except (ArgumentSchemaError, MCPRuntimeError) as exc:
            raise ToolError(str(exc)) from exc
        return result

    typed_tool.__name__ = f"netscan_{module}"
    typed_tool.__doc__ = (
        f"Start NetScan's {module} command as a background job using typed "
        "arguments derived from its native argparse definition. Only use against "
        "explicitly authorized targets."
    )

    required = [spec for spec in specs if spec.required]
    optional = [spec for spec in specs if not spec.required]
    parameters = []
    for spec in (*required, *optional):
        default = inspect.Parameter.empty if spec.required else spec.typed_default
        parameters.append(
            inspect.Parameter(
                spec.dest,
                kind=inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=_argument_type(spec, modules),
            )
        )
    if modules:
        parameters.append(
            inspect.Parameter(
                "module_args",
                kind=inspect.Parameter.KEYWORD_ONLY,
                default=None,
                annotation=Annotated[
                    list[str] | None,
                    Field(
                        description=(
                            "Additional positional arguments passed to the selected modules. "
                            "These follow the comma-separated module selection in the native CLI."
                        )
                    ),
                ],
            )
        )
    parameters.append(
        inspect.Parameter(
            "mcp_timeout_seconds",
            kind=inspect.Parameter.KEYWORD_ONLY,
            default=300,
            annotation=Annotated[
                int,
                Field(
                    ge=1,
                    le=maximum_timeout(),
                    description=(
                        "Maximum wall-clock runtime for the whole NetScan command. "
                        "This is separate from a scanner's network timeout option."
                    ),
                ),
            ],
        )
    )
    typed_tool.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        parameters=parameters,
        return_annotation=dict[str, object],
    )
    return typed_tool


def _register_typed_tools() -> None:
    for module in allowed_modules():
        specs = extract_argument_specs(PROJECT_ROOT / "scripts" / f"{module}.py")
        modules = extract_module_specs(
            PROJECT_ROOT / "scripts" / "lib" / module / "modules"
        )
        mcp.add_tool(
            _make_typed_tool(module, specs, modules),
            name=f"netscan_{module}",
            title=f"NetScan {module}",
            description=(
                f"Start the NetScan {module} command with strongly typed arguments "
                "generated from its argparse CLI definition."
            ),
        )


_register_typed_tools()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NetScan MCP server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind address")
    parser.add_argument("--port", type=int, default=8765, help="HTTP bind port")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.transport == "streamable-http":
        loopback_hosts = {"127.0.0.1", "localhost", "::1"}
        if args.host not in loopback_hosts and not env_flag("NETSCAN_MCP_ALLOW_REMOTE_HTTP"):
            raise SystemExit(
                "Refusing a non-loopback HTTP bind. Set "
                "NETSCAN_MCP_ALLOW_REMOTE_HTTP=true only behind appropriate authentication."
            )
        try:
            mcp.run(transport="streamable-http", host=args.host, port=args.port)
        finally:
            JOB_MANAGER.shutdown(wait=True)
    else:
        try:
            mcp.run(transport="stdio")
        finally:
            JOB_MANAGER.shutdown(wait=True)


if __name__ == "__main__":
    main()
