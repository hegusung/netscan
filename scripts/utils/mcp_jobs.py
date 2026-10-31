"""Bounded background scan jobs for the NetScan MCP server."""

from __future__ import annotations

import json
import mimetypes
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from utils.mcp_elasticsearch import elasticsearch_context
from utils.events import normalize_output_event
from utils.mcp_runtime import (
    ANSI_ESCAPE,
    MCPRuntimeError,
    PROJECT_ROOT,
    maximum_output,
    prepare_module,
    terminate_process_group,
)


TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled", "timed_out"})
SIGNIFICANT_EVENT_TYPES = frozenset(
    {"vuln", "major", "highlight", "success", "error"}
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _positive_env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise MCPRuntimeError(f"{name} must be an integer") from exc
    if value <= 0:
        raise MCPRuntimeError(f"{name} must be greater than zero")
    return value


@dataclass
class ScanJob:
    scan_id: str
    module: str
    arguments: tuple[str, ...]
    timeout_seconds: int
    elasticsearch: dict[str, Any]
    created_at: str = field(default_factory=_utc_now)
    state: str = "queued"
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    exit_code: int | None = None
    pid: int | None = None
    process: subprocess.Popen[bytes] | None = field(default=None, repr=False)
    future: Future[None] | None = field(default=None, repr=False)
    cancel_requested: threading.Event = field(
        default_factory=threading.Event, repr=False
    )
    output: bytearray = field(default_factory=bytearray, repr=False)
    total_output_bytes: int = 0
    output_truncated: bool = False
    events: list[dict[str, Any]] = field(default_factory=list, repr=False)
    event_summary: dict[str, Any] = field(default_factory=dict)
    internal_error: str | None = None
    artifact_dir: Path | None = field(default=None, repr=False)
    artifacts: list[dict[str, Any]] = field(default_factory=list)


ES_QUERY_DIRECTORY_EXPORTS = {
    "--export": "ports",
    "--export-hashes": "hashes",
    "--export-bloodhound": "bloodhound",
    "--parse-spns": "spns",
}


class ScanJobManager:
    """Run validated scanner commands in a bounded worker pool."""

    def __init__(
        self,
        *,
        max_workers: int | None = None,
        retention: int | None = None,
        output_limit: int | None = None,
        findings_limit: int | None = None,
        artifact_file_limit: int | None = None,
        artifact_total_limit: int | None = None,
    ) -> None:
        self.max_workers = max_workers or _positive_env_int(
            "NETSCAN_MCP_MAX_JOBS", 4
        )
        self.retention = retention or _positive_env_int(
            "NETSCAN_MCP_JOB_RETENTION", 100
        )
        self.output_limit = output_limit or maximum_output()
        self.findings_limit = findings_limit or _positive_env_int(
            "NETSCAN_MCP_MAX_FINDINGS", 200
        )
        self.artifact_file_limit = artifact_file_limit or _positive_env_int(
            "NETSCAN_MCP_MAX_ARTIFACT_BYTES", 25_000_000
        )
        self.artifact_total_limit = artifact_total_limit or _positive_env_int(
            "NETSCAN_MCP_MAX_ARTIFACT_TOTAL_BYTES", 100_000_000
        )
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers, thread_name_prefix="netscan-mcp-job"
        )

    def start(
        self, module: str, arguments: Sequence[str], timeout_seconds: int
    ) -> dict[str, Any]:
        prepared = prepare_module(module, arguments, timeout_seconds)
        es_context = elasticsearch_context(check_connection=False)
        es_context["persistence_expected"] = bool(
            es_context["enabled"] and "--nodb" not in prepared.arguments
        )
        es_context["run"] = {
            "reported": False,
            "documents_processed": None,
            "documents_indexed": None,
            "documents_failed": None,
            "documents_written_to_file": None,
        }
        job = ScanJob(
            scan_id=uuid.uuid4().hex,
            module=prepared.module,
            arguments=prepared.arguments,
            timeout_seconds=prepared.timeout_seconds,
            elasticsearch=es_context,
        )
        with self._lock:
            self._purge_locked(reserve=1)
            self._jobs[job.scan_id] = job
            job.future = self._executor.submit(self._execute, job, prepared)
            return self._status_locked(job)

    def status(self, scan_id: str) -> dict[str, Any]:
        with self._lock:
            return self._status_locked(self._get_locked(scan_id))

    def result(self, scan_id: str, *, include_findings: bool = True) -> dict[str, Any]:
        with self._lock:
            job = self._get_locked(scan_id)
            result = self._status_locked(job)
            result["summary"] = dict(job.event_summary)
            result["findings"] = list(job.events) if include_findings else []
            result["elasticsearch"] = job.elasticsearch
            result["artifacts"] = list(job.artifacts)
            return result

    def list_artifacts(self, scan_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._get_locked(scan_id)
            return {
                "scan_id": scan_id,
                "state": job.state,
                "artifacts": list(job.artifacts),
                "count": len(job.artifacts),
                "total_bytes": sum(item["size"] for item in job.artifacts),
            }

    def artifact_bytes(self, scan_id: str, artifact_id: str) -> bytes:
        with self._lock:
            job = self._get_locked(scan_id)
            artifact = next(
                (item for item in job.artifacts if item["artifact_id"] == artifact_id),
                None,
            )
            if artifact is None or job.artifact_dir is None:
                raise MCPRuntimeError(f"Unknown artifact_id: {artifact_id}")
            path = (job.artifact_dir / artifact["relative_path"]).resolve()
            root = job.artifact_dir.resolve()
            if path != root and root not in path.parents:
                raise MCPRuntimeError("Artifact path escaped its job directory")
            try:
                return path.read_bytes()
            except OSError as exc:
                raise MCPRuntimeError(f"Unable to read artifact: {exc}") from exc

    def list(self, *, state: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        if limit < 1 or limit > 100:
            raise MCPRuntimeError("limit must be between 1 and 100")
        if state is not None and state not in TERMINAL_STATES | {"queued", "running"}:
            raise MCPRuntimeError(f"Unknown scan state: {state}")
        with self._lock:
            jobs = sorted(
                self._jobs.values(), key=lambda item: item.created_at, reverse=True
            )
            if state is not None:
                jobs = [job for job in jobs if job.state == state]
            return [self._status_locked(job) for job in jobs[:limit]]

    def cancel(self, scan_id: str) -> dict[str, Any]:
        process: subprocess.Popen[bytes] | None = None
        with self._lock:
            job = self._get_locked(scan_id)
            if job.state in TERMINAL_STATES:
                return self._status_locked(job)
            job.cancel_requested.set()
            if job.state == "queued" and job.future is not None and job.future.cancel():
                job.state = "cancelled"
                job.completed_at = _utc_now()
            process = job.process
        if process is not None:
            terminate_process_group(process)
        return self.status(scan_id)

    def output_chunk(self, scan_id: str, offset: int, limit: int) -> dict[str, Any]:
        if offset < 0:
            raise MCPRuntimeError("offset must be zero or greater")
        if limit < 1 or limit > 100_000:
            raise MCPRuntimeError("limit must be between 1 and 100000")
        with self._lock:
            job = self._get_locked(scan_id)
            decoded = ANSI_ESCAPE.sub(
                "", bytes(job.output).decode("utf-8", errors="replace")
            )
            chunk = decoded[offset : offset + limit]
            return {
                "scan_id": scan_id,
                "state": job.state,
                "offset": offset,
                "next_offset": offset + len(chunk),
                "end_of_captured_output": offset + len(chunk) >= len(decoded),
                "truncated": job.output_truncated,
                "output": chunk,
            }

    def output_text(self, scan_id: str) -> str:
        with self._lock:
            job = self._get_locked(scan_id)
            decoded = ANSI_ESCAPE.sub(
                "", bytes(job.output).decode("utf-8", errors="replace")
            )
            if job.output_truncated:
                decoded += "\n[output truncated by NetScan MCP server]"
            return decoded

    def shutdown(self, *, wait: bool = False) -> None:
        with self._lock:
            active = [
                job for job in self._jobs.values() if job.state not in TERMINAL_STATES
            ]
        for job in active:
            self.cancel(job.scan_id)
        self._executor.shutdown(wait=wait, cancel_futures=True)
        with self._lock:
            for job in self._jobs.values():
                self._delete_artifacts_locked(job)

    def _get_locked(self, scan_id: str) -> ScanJob:
        try:
            return self._jobs[scan_id]
        except KeyError as exc:
            raise MCPRuntimeError(f"Unknown scan_id: {scan_id}") from exc

    def _purge_locked(self, *, reserve: int = 0) -> None:
        completed = sorted(
            (job for job in self._jobs.values() if job.state in TERMINAL_STATES),
            key=lambda item: item.completed_at or item.created_at,
        )
        excess = max(0, len(self._jobs) - self.retention + reserve)
        for job in completed[:excess]:
            self._jobs.pop(job.scan_id, None)
            self._delete_artifacts_locked(job)

    def _delete_artifacts_locked(self, job: ScanJob) -> None:
        if job.artifact_dir is not None:
            shutil.rmtree(job.artifact_dir, ignore_errors=True)
            job.artifact_dir = None
            job.artifacts = []

    def _status_locked(self, job: ScanJob) -> dict[str, Any]:
        return {
            "scan_id": job.scan_id,
            "state": job.state,
            "module": job.module,
            "argument_count": len(job.arguments),
            "timeout_seconds": job.timeout_seconds,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "duration_seconds": job.duration_seconds,
            "exit_code": job.exit_code,
            "pid": job.pid if job.state == "running" else None,
            "cancel_requested": job.cancel_requested.is_set(),
            "output": {
                "resource_uri": f"netscan://scans/{job.scan_id}/output",
                "captured_bytes": len(job.output),
                "total_bytes": job.total_output_bytes,
                "truncated": job.output_truncated,
            },
            "artifacts": {
                "count": len(job.artifacts),
                "total_bytes": sum(item["size"] for item in job.artifacts),
                "list_tool": "netscan_scan_artifacts",
            },
            "persistence_expected": job.elasticsearch["persistence_expected"],
            "internal_error": job.internal_error,
        }

    def _execute(self, job: ScanJob, prepared: Any) -> None:
        event_path: Path | None = None
        db_result_path: Path | None = None
        started = time.monotonic()
        try:
            if job.cancel_requested.is_set():
                with self._lock:
                    job.state = "cancelled"
                    job.completed_at = _utc_now()
                return

            event_file = tempfile.NamedTemporaryFile(
                prefix="netscan-mcp-events-", suffix=".jsonl", delete=False
            )
            event_path = Path(event_file.name)
            event_file.close()
            db_result_file = tempfile.NamedTemporaryFile(
                prefix="netscan-mcp-db-", suffix=".json", delete=False
            )
            db_result_path = Path(db_result_file.name)
            db_result_file.close()
            environment = dict(prepared.environment)
            environment["NETSCAN_MCP_EVENT_FILE"] = str(event_path)
            environment["NETSCAN_MCP_DB_RESULT_FILE"] = str(db_result_path)
            job.artifact_dir = Path(
                tempfile.mkdtemp(prefix=f"netscan-mcp-artifacts-{job.scan_id[:8]}-")
            )
            environment["NETSCAN_MCP_ARTIFACT_DIR"] = str(job.artifact_dir)
            prepared = self._confine_artifact_outputs(prepared, job.artifact_dir)

            process = subprocess.Popen(
                prepared.command,
                cwd=PROJECT_ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=(os.name == "posix"),
            )
            with self._lock:
                job.process = process
                job.pid = process.pid
                job.state = "running"
                job.started_at = _utc_now()

            reader = threading.Thread(
                target=self._drain_output,
                args=(job, process),
                name=f"netscan-mcp-output-{job.scan_id[:8]}",
                daemon=True,
            )
            reader.start()
            deadline = started + prepared.timeout_seconds
            timed_out = False
            while process.poll() is None:
                if job.cancel_requested.wait(timeout=0.1):
                    terminate_process_group(process)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    terminate_process_group(process)
                    break
            process.wait()
            reader.join(timeout=5)
            if reader.is_alive() and process.stdout is not None:
                process.stdout.close()
                reader.join(timeout=1)

            self._load_events(job, event_path)
            self._load_db_result(job, db_result_path)
            self._collect_artifacts(job)
            with self._lock:
                job.exit_code = process.returncode
                if job.cancel_requested.is_set():
                    job.state = "cancelled"
                elif timed_out:
                    job.state = "timed_out"
                elif process.returncode == 0:
                    job.state = "succeeded"
                else:
                    job.state = "failed"
        except Exception as exc:
            with self._lock:
                job.state = "cancelled" if job.cancel_requested.is_set() else "failed"
                job.internal_error = f"{type(exc).__name__}: {exc}"
        finally:
            if event_path is not None:
                try:
                    event_path.unlink()
                except FileNotFoundError:
                    pass
            if db_result_path is not None:
                try:
                    db_result_path.unlink()
                except FileNotFoundError:
                    pass
            with self._lock:
                job.process = None
                job.completed_at = job.completed_at or _utc_now()
                job.duration_seconds = round(time.monotonic() - started, 3)
                self._purge_locked()

    def _confine_artifact_outputs(self, prepared: Any, artifact_dir: Path) -> Any:
        if prepared.module != "es_query":
            return prepared

        arguments = list(prepared.arguments)
        for index, argument in enumerate(arguments[:-1]):
            subdirectory = ES_QUERY_DIRECTORY_EXPORTS.get(argument)
            if subdirectory is not None:
                destination = artifact_dir / subdirectory
                destination.mkdir(parents=True, exist_ok=True)
                arguments[index + 1] = str(destination)
            elif argument == "--dump":
                arguments[index + 1] = str(artifact_dir / "session-dump.jsonl")

        command = (*prepared.command[:2], *arguments)
        return replace(prepared, arguments=tuple(arguments), command=tuple(command))

    def _collect_artifacts(self, job: ScanJob) -> None:
        if job.artifact_dir is None:
            return
        root = job.artifact_dir.resolve()
        artifacts: list[dict[str, Any]] = []
        total = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            resolved = path.resolve()
            if root not in resolved.parents:
                continue
            size = resolved.stat().st_size
            if size > self.artifact_file_limit or total + size > self.artifact_total_limit:
                continue
            relative = resolved.relative_to(root).as_posix()
            artifact_id = uuid.uuid5(uuid.NAMESPACE_URL, f"{job.scan_id}:{relative}").hex
            mime_type = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
            artifacts.append(
                {
                    "artifact_id": artifact_id,
                    "name": resolved.name,
                    "relative_path": relative,
                    "size": size,
                    "mime_type": mime_type,
                    "sensitive": True,
                    "resource_uri": (
                        f"netscan://scans/{job.scan_id}/artifacts/{artifact_id}"
                    ),
                }
            )
            total += size
        with self._lock:
            job.artifacts = artifacts

    def _drain_output(
        self, job: ScanJob, process: subprocess.Popen[bytes]
    ) -> None:
        assert process.stdout is not None
        while chunk := process.stdout.read(65_536):
            with self._lock:
                job.total_output_bytes += len(chunk)
                remaining = self.output_limit - len(job.output)
                if remaining > 0:
                    job.output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    job.output_truncated = True
        process.stdout.close()

    def _load_events(self, job: ScanJob, event_path: Path) -> None:
        counts: Counter[str] = Counter()
        categories: Counter[str] = Counter()
        targets: set[str] = set()
        significant_total = 0
        findings: list[dict[str, Any]] = []
        try:
            lines = event_path.open("r", encoding="utf-8", errors="replace")
        except FileNotFoundError:
            lines = []
        with lines if hasattr(lines, "__enter__") else _NullContext(lines) as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    counts["invalid"] += 1
                    continue
                event = normalize_output_event(event)
                event_type = str(event.get("legacy_type", "normal"))
                category = str(event.get("category", "finding"))
                counts[event_type] += 1
                categories[category] += 1
                if event.get("target") is not None:
                    targets.add(str(event["target"]))
                if event_type in SIGNIFICANT_EVENT_TYPES:
                    significant_total += 1
                    if len(findings) < self.findings_limit:
                        findings.append(event)
        with self._lock:
            job.events = findings
            job.event_summary = {
                "total_events": sum(counts.values()),
                "event_types": dict(sorted(counts.items())),
                "event_categories": dict(sorted(categories.items())),
                "unique_targets": len(targets),
                "vulnerabilities": categories["vulnerability"],
                "errors": counts["error"],
                "significant_findings": significant_total,
                "findings_returned": len(findings),
                "findings_truncated": significant_total > len(findings),
            }

    def _load_db_result(self, job: ScanJob, result_path: Path) -> None:
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return
        if not isinstance(result, dict):
            return
        allowed = {
            "session",
            "persistence_disabled",
            "documents_processed",
            "documents_indexed",
            "documents_failed",
            "documents_written_to_file",
        }
        safe_result = {key: result[key] for key in allowed if key in result}
        safe_result["reported"] = True
        with self._lock:
            job.elasticsearch["run"] = safe_result


class _NullContext:
    def __init__(self, value: Any) -> None:
        self.value = value

    def __enter__(self) -> Any:
        return self.value

    def __exit__(self, *_args: Any) -> None:
        return None
