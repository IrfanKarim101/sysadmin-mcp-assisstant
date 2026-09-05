"""Two-step SSH host-key discovery and explicit-trust onboarding."""

from __future__ import annotations

import asyncio
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from time import monotonic
from uuid import uuid4

import asyncssh
from pydantic import BaseModel, ConfigDict, Field

from .config import HostConfig, ResourceThresholds, load_hosts, save_hosts, validate_host

PENDING_TTL_SECONDS = 300


class VMOnboardingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    hostname: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
    password_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,127}$")
    allowed_logs: list[str] = Field(min_length=1, max_length=20)
    cpu_threshold: float = Field(default=90.0, gt=0, le=100)
    memory_threshold: float = Field(default=90.0, gt=0, le=100)


@dataclass(frozen=True)
class PendingHostKey:
    request: VMOnboardingRequest
    public_key: bytes
    expires_at: float


class HostOnboardingService:
    def __init__(self, config_path: Path, known_hosts_path: Path) -> None:
        self.config_path = config_path
        self.known_hosts_path = known_hosts_path.resolve()
        self._pending: dict[str, PendingHostKey] = {}
        self._lock = asyncio.Lock()

    async def discover(self, request: VMOnboardingRequest) -> dict[str, object]:
        candidate = self._host_config(request)
        validate_host(candidate)
        existing = load_hosts(self.config_path) if self.config_path.exists() else {}
        if request.name in existing:
            raise ValueError(f"Host {request.name!r} already exists")
        async with asyncio.timeout(10):
            key = await asyncssh.get_server_host_key(request.hostname, request.port)
        if key is None:
            raise ConnectionError("The SSH server did not present a host key")
        token = str(uuid4())
        exported = key.export_public_key("openssh").strip()
        self._pending[token] = PendingHostKey(
            request=request,
            public_key=exported,
            expires_at=monotonic() + PENDING_TTL_SECONDS,
        )
        self._discard_expired()
        return {
            "token": token,
            "host": request.hostname,
            "port": request.port,
            "algorithm": key.get_algorithm(),
            "fingerprint": key.get_fingerprint("sha256"),
            "expires_in_seconds": PENDING_TTL_SECONDS,
        }

    async def decide(self, token: str, trust: bool) -> HostConfig | None:
        try:
            pending = self._pending.pop(token)
        except KeyError as error:
            raise ValueError("Unknown or expired host-key request") from error
        if pending.expires_at < monotonic():
            raise ValueError("Host-key request expired; discover the key again")
        if not trust:
            return None
        request = pending.request
        async with self._lock:
            async with asyncio.timeout(10):
                current = await asyncssh.get_server_host_key(request.hostname, request.port)
            if current is None or current.export_public_key("openssh").strip() != pending.public_key:
                raise ValueError("SSH host key changed before confirmation; nothing was saved")
            host = self._host_config(request)
            hosts = load_hosts(self.config_path) if self.config_path.exists() else {}
            if host.name in hosts:
                raise ValueError(f"Host {host.name!r} already exists")
            self._append_known_host(host, pending.public_key)
            hosts[host.name] = host
            save_hosts(self.config_path, hosts)
            return host

    def _host_config(self, request: VMOnboardingRequest) -> HostConfig:
        return HostConfig(
            name=request.name,
            hostname=request.hostname,
            port=request.port,
            username=request.username,
            known_hosts=str(self.known_hosts_path),
            client_keys=(),
            password_env=request.password_env,
            allowed_logs=frozenset(PurePosixPath(item) for item in request.allowed_logs),
            thresholds=ResourceThresholds(
                cpu_percent=request.cpu_threshold,
                memory_percent=request.memory_threshold,
            ),
        )

    def _append_known_host(self, host: HostConfig, public_key: bytes) -> None:
        self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        marker = host.hostname if host.port == 22 else f"[{host.hostname}]:{host.port}"
        entry = marker.encode("utf-8") + b" " + public_key + b"\n"
        existing = self.known_hosts_path.read_bytes() if self.known_hosts_path.exists() else b""
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.known_hosts_path.parent,
                prefix=f".{self.known_hosts_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary.write(existing + entry)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, self.known_hosts_path)
        except OSError:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise

    def _discard_expired(self) -> None:
        now = monotonic()
        self._pending = {
            token: pending
            for token, pending in self._pending.items()
            if pending.expires_at >= now
        }
