"""Configuration models and loading for approved target hosts.

Host configuration is deliberately separate from tool code. Connection details
and per-host log-path allowlists must be reviewable without editing the
executor's command policy.
"""

import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class HostConfig:
    """A single SSH target and the log files it permits reading."""

    name: str
    hostname: str
    username: str
    known_hosts: str | None
    client_keys: tuple[Path, ...]
    allowed_logs: frozenset[PurePosixPath]


def load_hosts(path: Path) -> dict[str, HostConfig]:
    """Load explicitly named targets from a TOML file."""
    with path.open("rb") as config_file:
        data = tomllib.load(config_file)

    hosts: dict[str, HostConfig] = {}
    for name, values in data.get("hosts", {}).items():
        allowed_logs = frozenset(PurePosixPath(item) for item in values["allowed_logs"])
        if not all(
            log.is_absolute()
            and ".." not in log.parts
            and not any(character in str(log) for character in ("\x00", "\n", "\r"))
            for log in allowed_logs
        ):
            raise ValueError(f"Host {name!r} has an unsafe allowed log path")
        hosts[name] = HostConfig(
            name=name,
            hostname=values["hostname"],
            username=values["username"],
            known_hosts=values.get("known_hosts"),
            client_keys=tuple(Path(item).expanduser() for item in values.get("client_keys", [])),
            allowed_logs=allowed_logs,
        )
    return hosts
