"""The trusted, fixed-command boundary for read-only SSH diagnostics."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .config import HostConfig
from .models import CommandResult
from .policy import MAX_LINES, PolicyError, ReadOnlyCommandPolicy
from .transport import AsyncSSHTransport, Transport

__all__ = [
    "AsyncSSHTransport",
    "CommandResult",
    "MAX_LINES",
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
        *,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        max_output_lines: int = MAX_OUTPUT_LINES,
    ) -> None:
        if max_output_bytes < 1 or max_output_lines < 1:
            raise ValueError("output limits must be positive")
        self._policy = ReadOnlyCommandPolicy(hosts)
        self._transport = transport
        self._max_output_bytes = max_output_bytes
        self._max_output_lines = max_output_lines

    async def check_ports(self, host: str) -> CommandResult:
        target = self._policy.host(host)
        result = await self._run(target, self._policy.ports())
        if result.exit_status == 127:
            return await self._run(target, self._policy.ports(fallback=True))
        return result

    async def check_services(self, host: str, state_filter: str | None = None) -> CommandResult:
        return await self._run(self._policy.host(host), self._policy.services(state_filter))

    async def check_resources(
        self, host: str
    ) -> tuple[CommandResult, CommandResult, CommandResult]:
        target = self._policy.host(host)
        top, free, vmstat = self._policy.resources()
        return (
            await self._run(target, top),
            await self._run(target, free),
            await self._run(target, vmstat),
        )

    async def read_log(self, host: str, logfile: str, mode: str, lines: int = 100) -> CommandResult:
        target = self._policy.host(host)
        return await self._run(target, self._policy.read_log(host, logfile, mode, lines))

    async def grep_log(
        self, host: str, logfile: str, pattern: str, max_lines: int = 100
    ) -> CommandResult:
        target = self._policy.host(host)
        return await self._run(target, self._policy.grep_log(host, logfile, pattern, max_lines))

    async def who_is_on(self, host: str) -> tuple[CommandResult, CommandResult]:
        target = self._policy.host(host)
        first, second = self._policy.active_users()
        return (await self._run(target, first), await self._run(target, second))

    async def _run(self, host: HostConfig, argv: Sequence[str]) -> CommandResult:
        result = await self._transport.run(host, argv)
        stdout, stdout_cut = self._bounded(result.stdout)
        stderr, stderr_cut = self._bounded(result.stderr)
        return CommandResult(
            tuple(argv), stdout, stderr, result.exit_status, stdout_cut or stderr_cut
        )

    def _bounded(self, value: str) -> tuple[str, bool]:
        lines = value.splitlines(keepends=True)
        line_limited = "".join(lines[: self._max_output_lines])
        encoded = line_limited.encode("utf-8")
        if len(encoded) > self._max_output_bytes:
            return encoded[: self._max_output_bytes].decode("utf-8", errors="ignore"), True
        return line_limited, len(lines) > self._max_output_lines
