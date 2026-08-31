"""SSH transport implementations; command authorization lives elsewhere."""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from typing import Protocol

from .config import HostConfig
from .models import CommandResult


class Transport(Protocol):
    """Execution seam; implementations receive only policy-created argv."""

    async def run(self, host: HostConfig, argv: Sequence[str]) -> CommandResult: ...


class AsyncSSHTransport:
    """AsyncSSH implementation which serializes a prevalidated argv safely."""

    def __init__(self, *, timeout_seconds: float = 15.0) -> None:
        self.timeout_seconds = timeout_seconds

    async def run(self, host: HostConfig, argv: Sequence[str]) -> CommandResult:
        # SSH exec requests are strings. shlex.join is POSIX-safe serialization;
        # this class has no public API accepting a caller-provided command string.
        import asyncssh

        command = tuple(argv)
        async with asyncssh.connect(
            host.hostname,
            username=host.username,
            known_hosts=host.known_hosts,
            client_keys=[str(key) for key in host.client_keys] or None,
            login_timeout=self.timeout_seconds,
        ) as connection:
            result = await connection.run(
                shlex.join(command), check=False, timeout=self.timeout_seconds
            )
        return CommandResult(command, result.stdout, result.stderr, result.exit_status)
