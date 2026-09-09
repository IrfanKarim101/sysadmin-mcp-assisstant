"""Approval-gated execution of fixed, host-allowlisted backup jobs."""
from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from time import monotonic, perf_counter
from uuid import uuid4

from .audit import AuditEvent, AuditSink
from .config import HostConfig
from .models import CommandResult
from .transport import Transport

APPROVAL_TTL_SECONDS = 120
MAX_PENDING_APPROVALS = 1_000


class BackupDenied(ValueError):
    pass


@dataclass(frozen=True)
class BackupApproval:
    username: str
    session_id: str
    host: str
    job: str
    expires_at: float


class BackupService:
    """Maps typed job IDs to the root helper; no script path enters this API."""

    def __init__(self, hosts: Mapping[str, HostConfig], transport: Transport, audit: AuditSink,
                 *, clock: Callable[[], float] = monotonic) -> None:
        self._hosts = dict(hosts)
        self._transport = transport
        self._audit = audit
        self._clock = clock
        self._approvals: dict[str, BackupApproval] = {}

    def replace_hosts(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    def jobs(self) -> list[dict[str, object]]:
        return [{"host": host.name, "backup_jobs": sorted(host.backup_jobs)}
                for host in self._hosts.values()]

    def preview(self, username: str, session_id: str, host: str, job: str) -> dict[str, object]:
        target, normalized = self._authorize(host, job)
        self._discard_expired()
        if len(self._approvals) >= MAX_PENDING_APPROVALS:
            raise BackupDenied("Approval capacity is temporarily exhausted")
        token = secrets.token_urlsafe(32)
        self._approvals[_digest(token)] = BackupApproval(
            username, session_id, target.name, normalized,
            self._clock() + APPROVAL_TTL_SECONDS,
        )
        return {
            "approval_token": token,
            "expires_in_seconds": APPROVAL_TTL_SECONDS,
            "host": target.name,
            "job": normalized,
            "effect": (
                f"Run the root-approved {normalized} backup job on {target.name}. "
                "The script may create database dump files and consume disk space."
            ),
        }

    async def execute(self, token: str, username: str, session_id: str) -> dict[str, object]:
        approval = self._approvals.pop(_digest(token), None)
        if approval is None or approval.expires_at < self._clock():
            raise BackupDenied("Approval is invalid, expired, or already used")
        if approval.username != username or approval.session_id != session_id:
            raise BackupDenied("Approval does not belong to this authenticated session")
        target, job = self._authorize(approval.host, approval.job)
        command = ("sudo", "-n", "/usr/local/bin/sysadmin-remediate", "run-backup", job)
        request_id, started = str(uuid4()), perf_counter()
        self._append(request_id, session_id, target.name, job, command, "attempted")
        try:
            result = await self._transport.run(target, command)
        except Exception as error:
            self._append(request_id, session_id, target.name, job, command, "error",
                         f"{type(error).__name__}: {error}", started)
            raise
        status = "success" if result.exit_status == 0 else "error"
        self._append(request_id, session_id, target.name, job, command, status,
                     result.stdout + result.stderr, started)
        return {"host": target.name, "job": job, "result": _result(result),
                "verified": result.exit_status == 0}

    def _authorize(self, host: str, job: str) -> tuple[HostConfig, str]:
        try:
            target = self._hosts[host]
        except KeyError as error:
            raise BackupDenied("Unknown or unapproved host") from error
        if job not in target.backup_jobs:
            raise BackupDenied("Backup job is not allowlisted for this host")
        return target, job

    def _discard_expired(self) -> None:
        now = self._clock()
        self._approvals = {
            key: value for key, value in self._approvals.items() if value.expires_at >= now
        }

    def _append(self, request_id: str, session_id: str, host: str, job: str,
                command: tuple[str, ...], status: str, output: str | None = None,
                started: float | None = None) -> None:
        self._audit.append(AuditEvent(
            request_id=request_id, session_id=session_id, target_host=host,
            tool_name="run_backup", parameters={"job": job}, command=command,
            status=status, output=output,
            duration_ms=None if started is None else round((perf_counter() - started) * 1000),
        ))


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _result(result: CommandResult) -> dict[str, object]:
    return {"command": list(result.command), "stdout": result.stdout, "stderr": result.stderr,
            "exit_status": result.exit_status, "truncated": result.truncated}
