"""Configuration models and loading for approved target hosts.

Host configuration is deliberately separate from tool code. Connection details
and per-host log-path allowlists must be reviewable without editing the
executor's command policy.
"""

import json
import os
import re
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

HOST_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
USERNAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,31}\Z")


class ConfigError(ValueError):
    """Host configuration is missing, malformed, or outside policy."""


@dataclass(frozen=True)
class ResourceThresholds:
    """Per-host percentages used by presentation anomaly checks."""

    cpu_percent: float = 90.0
    memory_percent: float = 90.0


@dataclass(frozen=True)
class HostConfig:
    """A single SSH target and the log files it permits reading."""

    name: str
    hostname: str
    username: str
    known_hosts: str | None
    client_keys: tuple[Path, ...]
    allowed_logs: frozenset[PurePosixPath]
    password_env: str | None = None
    thresholds: ResourceThresholds = ResourceThresholds()


def load_hosts(path: Path) -> dict[str, HostConfig]:
    """Load explicitly named targets from a TOML file."""
    try:
        with path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigError(f"Could not load host configuration: {path}") from error

    hosts: dict[str, HostConfig] = {}
    raw_hosts = data.get("hosts", {})
    if not isinstance(raw_hosts, dict):
        raise ConfigError("The hosts configuration must be a TOML table")
    for name, values in raw_hosts.items():
        if not isinstance(values, dict):
            raise ConfigError(f"Host {name!r} must be a TOML table")
        try:
            thresholds = values.get("thresholds", {})
            if not isinstance(thresholds, dict):
                raise TypeError("thresholds must be a table")
            host = HostConfig(
                name=name,
                hostname=values["hostname"],
                username=values["username"],
                known_hosts=str(Path(values["known_hosts"]).expanduser()),
                client_keys=tuple(
                    Path(item).expanduser()
                    for item in _string_list(
                        values["client_keys"], "client_keys", allow_empty=True
                    )
                ),
                password_env=values.get("password_env"),
                allowed_logs=frozenset(
                    PurePosixPath(item)
                    for item in _string_list(values["allowed_logs"], "allowed_logs")
                ),
                thresholds=ResourceThresholds(
                    cpu_percent=thresholds.get("cpu_percent", 90.0),
                    memory_percent=thresholds.get("memory_percent", 90.0),
                ),
            )
        except (KeyError, TypeError) as error:
            raise ConfigError(f"Host {name!r} is missing a required setting") from error
        validate_host(host)
        hosts[name] = host
    return hosts


def validate_host(host: HostConfig) -> None:
    """Validate one complete target without performing network or filesystem I/O."""
    if not HOST_NAME_PATTERN.fullmatch(host.name):
        raise ConfigError(f"Host name {host.name!r} is invalid")
    if (
        not isinstance(host.hostname, str)
        or not 1 <= len(host.hostname) <= 253
        or any(character in host.hostname for character in ("\x00", "\n", "\r"))
    ):
        raise ConfigError(f"Host {host.name!r} has an invalid hostname")
    if not isinstance(host.username, str) or not USERNAME_PATTERN.fullmatch(host.username):
        raise ConfigError(f"Host {host.name!r} has an invalid username")
    if (
        not isinstance(host.known_hosts, str)
        or not host.known_hosts.strip()
        or any(character in host.known_hosts for character in ("\x00", "\n", "\r"))
        or not Path(host.known_hosts).is_absolute()
    ):
        raise ConfigError(f"Host {host.name!r} must configure known_hosts")
    if host.client_keys and not all(
        isinstance(key, Path)
        and key.is_absolute()
        and not any(character in str(key) for character in ("\x00", "\n", "\r"))
        for key in host.client_keys
    ):
        raise ConfigError(f"Host {host.name!r} has an invalid client key")
    if host.password_env is not None and (
        not isinstance(host.password_env, str)
        or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", host.password_env)
    ):
        raise ConfigError(f"Host {host.name!r} has an invalid password_env")
    if not host.client_keys and not host.password_env:
        raise ConfigError(f"Host {host.name!r} must configure a client key or password_env")
    if not host.allowed_logs or not all(_safe_log_path(log) for log in host.allowed_logs):
        raise ConfigError(f"Host {host.name!r} has an unsafe allowed log path")
    for label, value in (
        ("cpu_percent", host.thresholds.cpu_percent),
        ("memory_percent", host.thresholds.memory_percent),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 100:
            raise ConfigError(f"Host {host.name!r} threshold {label} must be > 0 and <= 100")


def save_hosts(path: Path, hosts: dict[str, HostConfig]) -> None:
    """Atomically replace the configuration with validated, deterministically sorted TOML."""
    for name, host in hosts.items():
        if name != host.name:
            raise ConfigError("Host mapping key does not match HostConfig.name")
        validate_host(host)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = _serialize_hosts(hosts)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    except OSError as error:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise ConfigError(f"Could not save host configuration: {path}") from error


def _safe_log_path(log: PurePosixPath) -> bool:
    return (
        isinstance(log, PurePosixPath)
        and log.is_absolute()
        and ".." not in log.parts
        and not any(character in str(log) for character in ("\x00", "\n", "\r"))
    )


def _string_list(value: object, setting: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value) or not all(
        isinstance(item, str) for item in value
    ):
        raise ConfigError(f"{setting} must be a non-empty list of strings")
    return value


def _serialize_hosts(hosts: dict[str, HostConfig]) -> str:
    if not hosts:
        return "[hosts]\n"
    sections: list[str] = [
        "# Managed by sysadmin-hosts. Review changes before deploying."
    ]
    for name in sorted(hosts):
        host = hosts[name]
        table_name = json.dumps(name)
        sections.extend(
            (
                "",
                f"[hosts.{table_name}]",
                f"hostname = {json.dumps(host.hostname)}",
                f"username = {json.dumps(host.username)}",
                f"known_hosts = {json.dumps(str(host.known_hosts))}",
                "client_keys = " + _toml_array(str(key) for key in host.client_keys),
                *( [f"password_env = {json.dumps(host.password_env)}"] if host.password_env else [] ),
                "allowed_logs = " + _toml_array(str(log) for log in sorted(host.allowed_logs)),
                "",
                f"[hosts.{table_name}.thresholds]",
                f"cpu_percent = {float(host.thresholds.cpu_percent)}",
                f"memory_percent = {float(host.thresholds.memory_percent)}",
            )
        )
    return "\n".join(sections) + "\n"


def _toml_array(values) -> str:
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"
