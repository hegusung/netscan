"""Shared, protocol-agnostic credential campaign planning and state."""

from __future__ import annotations

import copy
import os
import random
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from utils.process_inputs import count_process_inputs, process_inputs


@dataclass(frozen=True)
class Account:
    username: str
    domain: str | None = None
    inline_secret: str | None = None


class CampaignState:
    """Thread-safe success/lockout state shared by protocol campaign workers."""

    def __init__(
        self, *, continue_on_success: bool = False, spray_round_delay: float = 0
    ) -> None:
        self.continue_on_success = continue_on_success
        self.spray_round_delay = max(0.0, float(spray_round_delay))
        self._successful: set[tuple[str, str, str]] = set()
        self._locked: set[tuple[str, str, str]] = set()
        self._in_flight: set[tuple[str, str, str]] = set()
        self._lock = threading.Lock()
        self._state_condition = threading.Condition(self._lock)
        self._round_condition = threading.Condition()
        self._current_round = 0
        self._round_remaining: dict[int, int] = {}
        self._next_round_at = 0.0

    @staticmethod
    def _account_key(
        target: dict, domain: str | None, username: str
    ) -> tuple[str, str, str]:
        normalized_domain = str(domain or "").lower()
        host = ""
        if normalized_domain in {"", "workgroup"}:
            host = str(target.get("hostname", "")).lower()
        return (host, normalized_domain, username.lower())

    @staticmethod
    def _attempt_key(
        target: dict, domain: str | None, username: str
    ) -> tuple[str, str, str]:
        return (
            str(target.get("hostname", "")).lower(),
            str(domain or "").lower(),
            username.lower(),
        )

    def should_attempt(self, target: dict, domain: str | None, username: str) -> bool:
        account = self._account_key(target, domain, username)
        success = self._attempt_key(target, domain, username)
        with self._lock:
            return account not in self._locked and (
                self.continue_on_success or success not in self._successful
            )

    def claim_attempt(self, target: dict, domain: str | None, username: str) -> bool:
        """Serialize attempts for one target/account and claim it when eligible."""
        account = self._account_key(target, domain, username)
        attempt = self._attempt_key(target, domain, username)
        with self._state_condition:
            while attempt in self._in_flight:
                self._state_condition.wait()
            if account in self._locked or (
                not self.continue_on_success and attempt in self._successful
            ):
                return False
            self._in_flight.add(attempt)
            return True

    def mark_success(self, target: dict, domain: str | None, username: str) -> None:
        with self._lock:
            self._successful.add(self._attempt_key(target, domain, username))

    def mark_locked(self, target: dict, domain: str | None, username: str) -> None:
        with self._lock:
            self._locked.add(self._account_key(target, domain, username))

    def begin_attempt(self, target: dict) -> None:
        round_id = target.get("b_spray_round")
        if round_id is None:
            return
        round_id = int(round_id)
        round_size = int(target.get("b_spray_round_size", 1))
        with self._round_condition:
            self._round_remaining.setdefault(round_id, round_size)
            while round_id > self._current_round:
                self._round_condition.wait()
            while time.monotonic() < self._next_round_at:
                self._round_condition.wait(self._next_round_at - time.monotonic())

    def complete_attempt(self, target: dict) -> None:
        attempt = self._attempt_key(
            target, target.get("b_domain"), str(target.get("b_username", ""))
        )
        with self._state_condition:
            self._in_flight.discard(attempt)
            self._state_condition.notify_all()

        round_id = target.get("b_spray_round")
        if round_id is None:
            return
        round_id = int(round_id)
        with self._round_condition:
            remaining = self._round_remaining.get(round_id, 1) - 1
            self._round_remaining[round_id] = remaining
            if remaining <= 0 and round_id == self._current_round:
                self._current_round += 1
                self._next_round_at = time.monotonic() + self.spray_round_delay
                self._round_condition.notify_all()


def apply_mcp_credential_environment(arguments) -> None:
    """Consume server-injected authentication material before child processes run."""
    mappings = {
        "password": "NETSCAN_MCP_CREDENTIAL_PASSWORD",
        "hash": "NETSCAN_MCP_CREDENTIAL_HASH",
        "community": "NETSCAN_MCP_CREDENTIAL_COMMUNITY",
    }
    for attribute, environment_name in mappings.items():
        value = os.environ.pop(environment_name, None)
        if hasattr(arguments, attribute) and getattr(arguments, attribute) is None:
            setattr(arguments, attribute, value)


def _read_nonempty(path: str | Path | None) -> list[str]:
    if path is None:
        return []
    with open(path, encoding="utf-8", errors="replace") as stream:
        return [line.strip() for line in stream if line.strip()]


def load_accounts(username_file: str | Path, default_domain: str | None = None) -> list[Account]:
    accounts: list[Account] = []
    for entry in _read_nonempty(username_file):
        username_part, separator, inline_secret = entry.partition(":")
        domain = default_domain
        username = username_part
        if "\\" in username_part:
            domain, username = username_part.split("\\", 1)
        accounts.append(
            Account(
                username=username,
                domain=domain,
                inline_secret=inline_secret if separator else None,
            )
        )
    return accounts


def iter_credential_attempts(
    target: dict,
    username_file: str | Path,
    secret_file: str | Path | None,
    *,
    default_domain: str | None = None,
    strategy: str = "bruteforce",
    secret_kind: str = "password",
    simple: bool = False,
    max_attempts_per_account: int | None = None,
) -> Iterator[dict]:
    """Yield individual attempts in per-account or password-spray order."""
    if strategy not in {"bruteforce", "spray"}:
        raise ValueError(f"Unknown credential campaign strategy: {strategy}")
    accounts = load_accounts(username_file, default_domain)
    secrets = _read_nonempty(secret_file)
    if max_attempts_per_account is not None:
        secrets = secrets[:max_attempts_per_account]

    def selected(account: Account) -> list[str]:
        if account.inline_secret is not None:
            return [account.inline_secret]
        if simple:
            return [account.username]
        return secrets

    if strategy == "spray" and not simple:
        def ordered_attempts():
            for account in accounts:
                if account.inline_secret is not None:
                    yield account, account.inline_secret
            for secret in secrets:
                for account in accounts:
                    if account.inline_secret is None:
                        yield account, secret

        ordered = ordered_attempts()
    else:
        ordered = (
            (account, secret)
            for account in accounts
            for secret in selected(account)
        )

    for account, secret in ordered:
        generated = copy.copy(target)
        generated["b_domain"] = account.domain
        generated["b_username"] = account.username
        generated["b_secret"] = secret
        generated["b_secret_kind"] = secret_kind
        yield generated


def credential_attempt_count(*args, **kwargs) -> int:
    return sum(1 for _ in iter_credential_attempts(*args, **kwargs))


def iter_target_credential_attempts(
    input_targets: dict,
    static_inputs: dict,
    username_file: str | Path,
    secret_file: str | Path | None,
    *,
    default_domain: str | None = None,
    strategy: str = "bruteforce",
    secret_kind: str = "password",
    simple: bool = False,
    max_attempts_per_account: int | None = None,
) -> Iterator[dict]:
    """Yield a campaign across the whole target scope without materializing targets."""
    accounts = load_accounts(username_file, default_domain)
    secrets = _read_nonempty(secret_file)
    if max_attempts_per_account is not None:
        secrets = secrets[:max_attempts_per_account]

    if strategy == "spray" and not simple:
        for target in process_inputs(input_targets, static_inputs):
            for account in accounts:
                if account.inline_secret is not None:
                    yield _attempt(target, account, account.inline_secret, secret_kind)

        spray_accounts = [account for account in accounts if account.inline_secret is None]
        round_size = count_process_inputs(input_targets, static_inputs) * len(spray_accounts)
        for round_id, secret in enumerate(secrets):
            for target in process_inputs(input_targets, static_inputs):
                for account in spray_accounts:
                    attempt = _attempt(target, account, secret, secret_kind)
                    attempt["b_spray_round"] = round_id
                    attempt["b_spray_round_size"] = round_size
                    yield attempt
        return

    for target in process_inputs(input_targets, static_inputs):
        for account in accounts:
            if account.inline_secret is not None:
                selected = [account.inline_secret]
            elif simple:
                selected = [account.username]
            else:
                selected = secrets
            for secret in selected:
                yield _attempt(target, account, secret, secret_kind)


def target_credential_attempt_count(
    input_targets: dict,
    static_inputs: dict,
    username_file: str | Path,
    secret_file: str | Path | None,
    *,
    default_domain: str | None = None,
    strategy: str = "bruteforce",
    secret_kind: str = "password",
    simple: bool = False,
    max_attempts_per_account: int | None = None,
) -> int:
    del strategy, secret_kind
    accounts = load_accounts(username_file, default_domain)
    secrets = _read_nonempty(secret_file)
    if max_attempts_per_account is not None:
        secrets = secrets[:max_attempts_per_account]
    attempts_per_target = 0
    for account in accounts:
        if account.inline_secret is not None or simple:
            attempts_per_target += 1
        else:
            attempts_per_target += len(secrets)
    return count_process_inputs(input_targets, static_inputs) * attempts_per_target


def iter_target_secret_attempts(
    input_targets: dict,
    static_inputs: dict,
    secret_file: str | Path,
    *,
    username: str = "N/A",
    secret_kind: str = "password",
    strategy: str = "bruteforce",
    max_attempts_per_account: int | None = None,
) -> Iterator[dict]:
    secrets = _read_nonempty(secret_file)
    if max_attempts_per_account is not None:
        secrets = secrets[:max_attempts_per_account]
    target_count = count_process_inputs(input_targets, static_inputs)
    if strategy == "spray":
        for round_id, secret in enumerate(secrets):
            for target in process_inputs(input_targets, static_inputs):
                attempt = copy.copy(target)
                attempt.update(
                    {
                        "b_domain": None,
                        "b_username": username,
                        "b_secret": secret,
                        "b_secret_kind": secret_kind,
                        "b_spray_round": round_id,
                        "b_spray_round_size": target_count,
                    }
                )
                yield attempt
        return
    for target in process_inputs(input_targets, static_inputs):
        for secret in secrets:
            attempt = copy.copy(target)
            attempt.update(
                {
                    "b_domain": None,
                    "b_username": username,
                    "b_secret": secret,
                    "b_secret_kind": secret_kind,
                }
            )
            yield attempt


def target_secret_attempt_count(
    input_targets: dict,
    static_inputs: dict,
    secret_file: str | Path,
    *,
    max_attempts_per_account: int | None = None,
    **_options,
) -> int:
    secrets = _read_nonempty(secret_file)
    if max_attempts_per_account is not None:
        secrets = secrets[:max_attempts_per_account]
    return count_process_inputs(input_targets, static_inputs) * len(secrets)


def dispatch_credential_campaign(
    input_targets: dict,
    static_inputs: dict,
    settings: dict,
    worker,
    *,
    timeout: int,
    default_domain: str | None = None,
    username: str | None = None,
    secret_kind: str = "password",
    progress_name: str = "Credentials",
) -> None:
    """Dispatch one scope-wide campaign using the common worker contract."""
    from utils.dispatch import dispatch

    common = {
        "strategy": settings.get("strategy", "bruteforce"),
        "secret_kind": secret_kind,
        "max_attempts_per_account": settings.get("max_attempts_per_account"),
    }
    username_file = settings.get("username_file")
    secret_file = settings.get("password_file") or settings.get("secret_file")
    if username_file is None:
        generator = iter_target_secret_attempts(
            input_targets,
            static_inputs,
            secret_file,
            username=username or "N/A",
            **common,
        )
        size = target_secret_attempt_count(
            input_targets,
            static_inputs,
            secret_file,
            **common,
        )
    else:
        common.update(
            {
                "default_domain": default_domain,
                "simple": settings.get("simple", False),
            }
        )
        generator = iter_target_credential_attempts(
            input_targets, static_inputs, username_file, secret_file, **common
        )
        size = target_credential_attempt_count(
            input_targets, static_inputs, username_file, secret_file, **common
        )
    state = CampaignState(
        continue_on_success=settings.get("continue_on_success", False),
        spray_round_delay=settings.get("spray_round_delay", 0),
    )
    dispatch(
        generator,
        size,
        worker,
        (
            timeout,
            settings.get("delay", 0),
            settings.get("jitter", 0),
            state,
        ),
        workers=settings.get("workers", 1),
        process=False,
        pg_name=progress_name,
    )


def _attempt(target: dict, account: Account, secret: str, secret_kind: str) -> dict:
    generated = copy.copy(target)
    generated["b_domain"] = account.domain
    generated["b_username"] = account.username
    generated["b_secret"] = secret
    generated["b_secret_kind"] = secret_kind
    return generated


def wait_before_attempt(delay: float = 0, jitter: float = 0) -> None:
    duration = max(0.0, float(delay))
    if jitter > 0:
        duration += random.uniform(0, float(jitter))
    if duration:
        time.sleep(duration)


def record_credential_validation(
    target: dict,
    *,
    service: str,
    username: str,
    secret: str,
    status: str,
    url: str,
    domain: str | None = None,
    secret_kind: str = "password",
    admin: bool = False,
    source: str = "campaign",
) -> str:
    """Persist a secret-free validation result and return its correlation ref."""
    from utils.db import DB

    credential_ref = DB.credential_reference(domain, username, secret_kind, secret)
    DB.insert_credential_validation(
        {
            "credential_ref": credential_ref,
            "host": target.get("hostname"),
            "port": target.get("port"),
            "url": url,
            "service": service,
            "domain": domain,
            "username": username,
            "secret_kind": secret_kind,
            "status": status,
            "admin": bool(admin),
            "source": source,
        }
    )
    return credential_ref
