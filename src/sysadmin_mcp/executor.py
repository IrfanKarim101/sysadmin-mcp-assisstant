"""The trusted, fixed-command boundary for read-only SSH diagnostics."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from time import perf_counter
from uuid import uuid4

from .audit import AuditEvent, AuditSink
from .config import HostConfig
from .models import CommandResult
from .policy import MAX_LINES, PolicyError, ReadOnlyCommandPolicy
from .transport import AsyncSSHTransport, Transport

__all__ = [
    "MAX_LINES",
    "AsyncSSHTransport",
    "CommandResult",
    "PolicyError",
    "ReadOnlyExecutor",
    "SSHTransport",
]

MAX_OUTPUT_BYTES = 256 * 1024
MAX_OUTPUT_LINES = 2_000


# Backwards-compatible name for callers which imported the original protocol.
SSHTransport = Transport


class ReadOnlyExecutor:
    """Read-only diagnostic capability surface with no generic execution API."""

    def __init__(
        self,
        hosts: Mapping[str, HostConfig],
        transport: Transport,
        audit: AuditSink,
        *,
        session_id: str | None = None,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        max_output_lines: int = MAX_OUTPUT_LINES,
    ) -> None:
        if max_output_bytes < 1 or max_output_lines < 1:
            raise ValueError("output limits must be positive")
        self._policy = ReadOnlyCommandPolicy(hosts)
        self._transport = transport
        self._audit = audit
        self._session_id = session_id
        self._max_output_bytes = max_output_bytes
        self._max_output_lines = max_output_lines

    def replace_hosts(self, hosts: Mapping[str, HostConfig]) -> None:
        """Atomically replace the approved target set after admin onboarding."""
        self._policy = ReadOnlyCommandPolicy(hosts)

    async def check_ports(self, host: str) -> CommandResult:
        parameters: dict[str, object] = {}
        try:
            target = self._policy.host(host)
        except PolicyError:
            self._audit_denied(host, "check_ports", parameters)
            raise
        result = await self._run(target, self._policy.ports(), "check_ports", parameters)
        if result.exit_status == 127:
            return await self._run(
                target, self._policy.ports(fallback=True), "check_ports", parameters
            )
        return result

    async def check_services(self, host: str, state_filter: str | None = None) -> CommandResult:
        parameters = {"state_filter": state_filter}
        try:
            target = self._policy.host(host)
            command = self._policy.services(state_filter)
        except PolicyError:
            self._audit_denied(host, "check_services", parameters)
            raise
        return await self._run(target, command, "check_services", parameters)

    async def check_resources(
        self, host: str
    ) -> tuple[CommandResult, CommandResult, CommandResult]:
        parameters: dict[str, object] = {}
        try:
            target = self._policy.host(host)
        except PolicyError:
            self._audit_denied(host, "check_resources", parameters)
            raise
        top, free, vmstat = self._policy.resources()
        return (
            await self._run(target, top, "check_resources", parameters),
            await self._run(target, free, "check_resources", parameters),
            await self._run(target, vmstat, "check_resources", parameters),
        )

    async def check_disk_usage(self, host: str) -> tuple[CommandResult, ...]:
        return await self._fixed_many(host, "check_disk_usage", self._policy.disk_usage())

    async def check_top_processes(self, host: str) -> tuple[CommandResult, ...]:
        return await self._fixed_many(host, "check_top_processes", self._policy.top_processes())

    async def check_network(self, host: str) -> tuple[CommandResult, ...]:
        return await self._fixed_many(host, "check_network", self._policy.network_status())

    async def check_docker(self, host: str) -> tuple[CommandResult, ...]:
        return await self._fixed_many(host, "check_docker", self._policy.docker_status())

    async def read_log(self, host: str, logfile: str, mode: str, lines: int = 100) -> CommandResult:
        parameters = {"logfile": logfile, "mode": mode, "lines": lines}
        try:
            target = self._policy.host(host)
            command = self._policy.read_log(host, logfile, mode, lines)
        except PolicyError:
            self._audit_denied(host, "read_log", parameters)
            raise
        return await self._run(target, command, "read_log", parameters)

    async def grep_log(
        self, host: str, logfile: str, pattern: str, max_lines: int = 100
    ) -> CommandResult:
        parameters = {"logfile": logfile, "pattern": pattern, "max_lines": max_lines}
        try:
            target = self._policy.host(host)
            command = self._policy.grep_log(host, logfile, pattern, max_lines)
        except PolicyError:
            self._audit_denied(host, "grep_log", parameters)
            raise
        return await self._run(target, command, "grep_log", parameters)

    async def who_is_on(self, host: str) -> tuple[CommandResult, CommandResult]:
        parameters: dict[str, object] = {}
        try:
            target = self._policy.host(host)
        except PolicyError:
            self._audit_denied(host, "who_is_on", parameters)
            raise
        first, second = self._policy.active_users()
        return (
            await self._run(target, first, "who_is_on", parameters),
            await self._run(target, second, "who_is_on", parameters),
        )

    async def _fixed_many(
        self, host: str, tool_name: str, commands: Sequence[Sequence[str]]
    ) -> tuple[CommandResult, ...]:
        parameters: dict[str, object] = {}
        try:
            target = self._policy.host(host)
        except PolicyError:
            self._audit_denied(host, tool_name, parameters)
            raise
        return tuple(
            [await self._run(target, command, tool_name, parameters) for command in commands]
        )

    async def _run(
        self,
        host: HostConfig,
        argv: Sequence[str],
        tool_name: str,
        parameters: Mapping[str, object],
    ) -> CommandResult:
        request_id = str(uuid4())
        self._append_audit(request_id, host.name, tool_name, parameters, argv, "attempted")
        started = perf_counter()
        try:
            result = await self._transport.run(host, argv)
        except Exception as error:
            duration_ms = round((perf_counter() - started) * 1_000)
            self._append_audit(
                request_id,
                host.name,
                tool_name,
                parameters,
                argv,
                "error",
                output=f"{type(error).__name__}: {error}",
                duration_ms=duration_ms,
            )
            raise
        duration_ms = round((perf_counter() - started) * 1_000)
        raw_output = result.stdout + result.stderr
        self._append_audit(
            request_id,
            host.name,
            tool_name,
            parameters,
            argv,
            "success" if result.exit_status == 0 else "error",
            output=raw_output,
            duration_ms=duration_ms,
        )
        stdout, stdout_cut = self._bounded(result.stdout)
        stderr, stderr_cut = self._bounded(result.stderr)
        return CommandResult(
            tuple(argv),
            stdout,
            stderr,
            result.exit_status,
            result.truncated or stdout_cut or stderr_cut,
        )

    def _audit_denied(
        self, host: str, tool_name: str, parameters: Mapping[str, object]
    ) -> None:
        self._append_audit(
            str(uuid4()), host, tool_name, parameters, (), "denied"
        )

    def _append_audit(
        self,
        request_id: str,
        host: str,
        tool_name: str,
        parameters: Mapping[str, object],
        command: Sequence[str],
        status: str,
        *,
        output: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        self._audit.append(
            AuditEvent(
                request_id=request_id,
                session_id=self._session_id,
                target_host=host,
                tool_name=tool_name,
                parameters=parameters,
                command=command,
                status=status,
                output=output,
                duration_ms=duration_ms,
            )
        )

    def _bounded(self, value: str) -> tuple[str, bool]:
        lines = value.splitlines(keepends=True)
        line_limited = "".join(lines[: self._max_output_lines])
        encoded = line_limited.encode("utf-8")
        if len(encoded) > self._max_output_bytes:
            return encoded[: self._max_output_bytes].decode("utf-8", errors="ignore"), True
        return line_limited, len(lines) > self._max_output_lines
