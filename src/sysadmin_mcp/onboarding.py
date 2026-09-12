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
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from .config import HostConfig, ResourceThresholds, load_hosts, save_hosts, validate_host
from .credential_vault import CredentialVault

PENDING_TTL_SECONDS = 300


class VMOnboardingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    hostname: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
    password: SecretStr | None = Field(default=None, min_length=1, max_length=256)
    password_env: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{0,127}$")
    allowed_logs: list[str] = Field(min_length=1, max_length=20)
    cpu_threshold: float = Field(default=90.0, gt=0, le=100)
    memory_threshold: float = Field(default=90.0, gt=0, le=100)
    restart_services: list[str] = Field(default_factory=list, max_length=10)
    backup_jobs: list[str] = Field(default_factory=list, max_length=10)
    environment: str = Field(
        default="production",
        pattern=r"^(production|staging|development|disposable_lab)$",
    )

    @model_validator(mode="after")
    def credential(self):
        if self.password is None and self.password_env is None:
            raise ValueError("password is required")
        return self


@dataclass(frozen=True)
class PendingHostKey:
    request: VMOnboardingRequest
    public_key: bytes
    expires_at: float


class HostOnboardingService:
    def __init__(self, config_path: Path, known_hosts_path: Path,
                 vault: CredentialVault | None = None) -> None:
        self.config_path = config_path
        self.known_hosts_path = known_hosts_path.resolve()
        self._pending: dict[str, PendingHostKey] = {}
        self._lock = asyncio.Lock()
        self.vault = vault

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
            if request.password is not None:
                if self.vault is None:
                    raise RuntimeError("Encrypted credential vault is unavailable")
                self.vault.set(host.name, request.password.get_secret_value())
            return host

    async def remove(self, name: str) -> HostConfig:
        """Remove one managed host and only its exact known-hosts entry."""
        async with self._lock:
            hosts = load_hosts(self.config_path)
            try:
                host = hosts.pop(name)
            except KeyError as error:
                raise ValueError(f"Host {name!r} does not exist") from error
            save_hosts(self.config_path, hosts)
            self._remove_known_host(host)
            if self.vault is not None:
                self.vault.delete(host.name)
            return host

    async def classify(self, name: str, environment: str) -> HostConfig:
        async with self._lock:
            hosts = load_hosts(self.config_path)
            try:
                current = hosts[name]
            except KeyError as error:
                raise ValueError(f"Host {name!r} does not exist") from error
            updated = HostConfig(**{**current.__dict__, "environment": environment})
            validate_host(updated)
            hosts[name] = updated
            save_hosts(self.config_path, hosts)
            return updated

    def _host_config(self, request: VMOnboardingRequest) -> HostConfig:
        return HostConfig(
            name=request.name,
            hostname=request.hostname,
            port=request.port,
            username=request.username,
            known_hosts=str(self.known_hosts_path),
            client_keys=(),
            password_env=request.password_env or f"SENTINEL_VAULT_{request.name.upper().replace('-', '_')}",
            allowed_logs=frozenset(PurePosixPath(item) for item in request.allowed_logs),
            thresholds=ResourceThresholds(
                cpu_percent=request.cpu_threshold,
                memory_percent=request.memory_threshold,
            ),
            restart_services=frozenset(request.restart_services),
            backup_jobs=frozenset(request.backup_jobs),
            environment=request.environment,
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

    def _remove_known_host(self, host: HostConfig) -> None:
        if not self.known_hosts_path.exists():
            return
        marker = host.hostname if host.port == 22 else f"[{host.hostname}]:{host.port}"
        lines = self.known_hosts_path.read_bytes().splitlines(keepends=True)
        kept = [line for line in lines if line.split(b" ", 1)[0] != marker.encode()]
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.known_hosts_path.parent, prefix=f".{self.known_hosts_path.name}.",
                suffix=".tmp", delete=False,
            ) as temporary:
                temporary.writelines(kept)
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
