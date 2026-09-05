"""SSH transport implementations; command authorization lives elsewhere."""

from __future__ import annotations

import asyncio
import os
import shlex
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from .config import HostConfig
from .models import CommandResult

MAX_TRANSPORT_OUTPUT_BYTES = 256 * 1024
READ_CHUNK_SIZE = 8 * 1024


class Transport(Protocol):
    """Execution seam; implementations receive only policy-created argv."""

    async def run(self, host: HostConfig, argv: Sequence[str]) -> CommandResult: ...


class AsyncSSHTransport:
    """AsyncSSH implementation which serializes a prevalidated argv safely."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 15.0,
        max_output_bytes: int = MAX_TRANSPORT_OUTPUT_BYTES,
    ) -> None:
        if timeout_seconds <= 0 or max_output_bytes < 1:
            raise ValueError("transport limits must be positive")
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    async def run(self, host: HostConfig, argv: Sequence[str]) -> CommandResult:
        # SSH exec requests are strings. shlex.join is POSIX-safe serialization;
        # this class has no public API accepting a caller-provided command string.
        import asyncssh

        command = tuple(argv)
        password = os.environ.get(host.password_env) if host.password_env else None
        if host.password_env and password is None:
            raise RuntimeError(f"required credential environment variable is not set: {host.password_env}")
        async with asyncssh.connect(
            host.hostname,
            port=host.port,
            username=host.username,
            known_hosts=host.known_hosts,
            client_keys=[str(key) for key in host.client_keys] or None,
            password=password,
            login_timeout=self.timeout_seconds,
        ) as connection:
            process = await connection.create_process(
                shlex.join(command), encoding="utf-8", errors="replace"
            )

            def stop_process() -> None:
                process.terminate()
                process.close()

            async with asyncio.timeout(self.timeout_seconds):
                (stdout, stdout_cut), (stderr, stderr_cut) = await asyncio.gather(
                    _read_bounded_stream(
                        process.stdout, self.max_output_bytes, stop_process
                    ),
                    _read_bounded_stream(
                        process.stderr, self.max_output_bytes, stop_process
                    ),
                )
                await process.wait_closed()
        exit_status = process.exit_status if process.exit_status is not None else 255
        return CommandResult(
            command, stdout, stderr, exit_status, stdout_cut or stderr_cut
        )


async def _read_bounded_stream(
    reader: Any, limit: int, stop_process: Callable[[], None]
) -> tuple[str, bool]:
    """Drain one SSH stream without retaining more than ``limit`` UTF-8 bytes."""
    chunks: list[str] = []
    retained_bytes = 0
    while True:
        chunk = await reader.read(READ_CHUNK_SIZE)
        if not chunk:
            return "".join(chunks), False
        encoded = chunk.encode("utf-8")
        remaining = limit - retained_bytes
        if len(encoded) <= remaining:
            chunks.append(chunk)
            retained_bytes += len(encoded)
            continue
        chunks.append(encoded[:remaining].decode("utf-8", errors="ignore"))
        stop_process()
        return "".join(chunks), True
