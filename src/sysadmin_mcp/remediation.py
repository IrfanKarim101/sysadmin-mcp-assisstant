"""Approval-gated fixed remediation actions, isolated from diagnostic execution."""
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
STATUS_PROPERTIES = "ActiveState,SubState,Result,ExecMainStatus"


class RemediationDenied(ValueError):
    pass


@dataclass(frozen=True)
class Approval:
    username: str
    session_id: str
    host: str
    service: str
    expires_at: float


class RemediationService:
    """Exposes typed actions only; it has no generic command method."""

    def __init__(self, hosts: Mapping[str, HostConfig], transport: Transport, audit: AuditSink,
                 *, clock: Callable[[], float] = monotonic) -> None:
        self._hosts = dict(hosts)
        self._transport = transport
        self._audit = audit
        self._clock = clock
        self._approvals: dict[str, Approval] = {}

    def replace_hosts(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    def actions(self) -> list[dict[str, object]]:
        return [{"host": host.name, "restart_services": sorted(host.restart_services)}
                for host in self._hosts.values()]

    async def preview_restart(self, username: str, session_id: str, host: str,
                              service: str) -> dict[str, object]:
        target, normalized = self._authorize(host, service)
        before = await self._audited_run(
            target, self._status_command(normalized), "restart_service_preview",
            normalized, session_id,
        )
        if before.exit_status != 0:
            raise RemediationDenied("Current service state could not be verified")
        self._discard_expired()
        if len(self._approvals) >= MAX_PENDING_APPROVALS:
            raise RemediationDenied("Approval capacity is temporarily exhausted")
        token = secrets.token_urlsafe(32)
        self._approvals[_digest(token)] = Approval(
            username, session_id, host, normalized, self._clock() + APPROVAL_TTL_SECONDS
        )
        return {
            "approval_token": token, "expires_in_seconds": APPROVAL_TTL_SECONDS,
            "host": host, "service": normalized,
            "effect": f"Restart {normalized} on {host}. Existing connections may be interrupted.",
            "before": _result(before),
        }

    async def execute_restart(self, token: str, username: str,
                              session_id: str) -> dict[str, object]:
        approval = self._approvals.pop(_digest(token), None)
        if approval is None or approval.expires_at < self._clock():
            raise RemediationDenied("Approval is invalid, expired, or already used")
        if approval.username != username or approval.session_id != session_id:
            raise RemediationDenied("Approval does not belong to this authenticated session")
        target, service = self._authorize(approval.host, approval.service)
        command = (
            "sudo", "-n", "/usr/local/bin/sysadmin-remediate", "restart-service", service
        )
        request_id, started = str(uuid4()), perf_counter()
        self._append(request_id, session_id, target.name, service, command, "attempted")
        try:
            action = await self._transport.run(target, command)
            after = await self._audited_run(
                target, self._status_command(service), "restart_service_verify", service, session_id
            )
        except Exception as error:
            self._append(request_id, session_id, target.name, service, command, "error",
                         f"{type(error).__name__}: {error}", started)
            raise
        status = "success" if action.exit_status == 0 else "error"
        self._append(request_id, session_id, target.name, service, command, status,
                     action.stdout + action.stderr, started)
        verified = action.exit_status == 0 and after.exit_status == 0 and _is_active(after.stdout)
        return {"host": target.name, "service": service, "action": _result(action),
                "after": _result(after), "verified": verified}

    def _authorize(self, host: str, service: str) -> tuple[HostConfig, str]:
        try:
            target = self._hosts[host]
        except KeyError as error:
            raise RemediationDenied("Unknown or unapproved host") from error
        if service not in target.restart_services:
            raise RemediationDenied("Service restart is not allowlisted for this host")
        return target, service

    @staticmethod
    def _status_command(service: str) -> tuple[str, ...]:
        return ("systemctl", "show", service, "--no-pager", f"--property={STATUS_PROPERTIES}")

    def _discard_expired(self) -> None:
        now = self._clock()
        self._approvals = {key: value for key, value in self._approvals.items()
                           if value.expires_at >= now}

    async def _audited_run(self, target: HostConfig, command: tuple[str, ...], tool: str,
                           service: str, session_id: str) -> CommandResult:
        request_id, started = str(uuid4()), perf_counter()
        self._append(request_id, session_id, target.name, service, command, "attempted", tool=tool)
        try:
            result = await self._transport.run(target, command)
        except Exception as error:
            self._append(request_id, session_id, target.name, service, command, "error",
                         f"{type(error).__name__}: {error}", started, tool)
            raise
        self._append(request_id, session_id, target.name, service, command,
                     "success" if result.exit_status == 0 else "error",
                     result.stdout + result.stderr, started, tool)
        return result

    def _append(self, request_id: str, session_id: str, host: str, service: str,
                command: tuple[str, ...],
                status: str, output: str | None = None, started: float | None = None,
                tool: str = "restart_service") -> None:
        self._audit.append(AuditEvent(
            request_id=request_id, session_id=session_id, target_host=host,
            tool_name=tool, parameters={"service": service}, command=command,
            status=status, output=output,
            duration_ms=None if started is None else round((perf_counter()-started)*1000),
        ))


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _result(result: CommandResult) -> dict[str, object]:
    return {"command": list(result.command), "stdout": result.stdout, "stderr": result.stderr,
            "exit_status": result.exit_status, "truncated": result.truncated}


def _is_active(output: str) -> bool:
    return any(line.strip() == "ActiveState=active" for line in output.splitlines())
