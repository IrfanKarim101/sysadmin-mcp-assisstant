import json
from pathlib import Path, PurePosixPath

import pytest

from sysadmin_mcp.config import (
    ConfigError,
    HostConfig,
    ResourceThresholds,
    load_hosts,
    save_hosts,
)
from sysadmin_mcp.policy import PolicyError, ReadOnlyCommandPolicy


def connection_settings(tmp_path: Path) -> str:
    known_hosts = json.dumps(str(tmp_path / "known_hosts"))
    client_key = json.dumps(str(tmp_path / "id_readonly"))
    return f"known_hosts = {known_hosts}\nclient_keys = [{client_key}]\n"


@pytest.mark.parametrize("path", ["../etc/shadow", "/var/log/../shadow"])
def test_config_rejects_unsafe_allowlist_paths(tmp_path: Path, path: str) -> None:
    config = tmp_path / "hosts.toml"
    config.write_text(
        "[hosts.test]\n"
        + 'hostname = "localhost"\n'
        + 'username = "reader"\n'
        + connection_settings(tmp_path)
        + f'allowed_logs = ["{path}"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsafe allowed log path"):
        load_hosts(config)


def test_config_drives_per_host_log_allowlists(tmp_path: Path) -> None:
    config = tmp_path / "hosts.toml"
    config.write_text(
        "[hosts.web]\n"
        + 'hostname = "web.internal"\n'
        + 'username = "reader"\n'
        + connection_settings(tmp_path)
        + 'allowed_logs = ["/var/log/nginx/error.log"]\n\n'
        + "[hosts.db]\n"
        + 'hostname = "db.internal"\n'
        + 'username = "reader"\n'
        + connection_settings(tmp_path)
        + 'allowed_logs = ["/var/log/postgresql/postgresql.log"]\n',
        encoding="utf-8",
    )
    hosts = load_hosts(config)
    assert {str(path) for path in hosts["web"].allowed_logs} == {"/var/log/nginx/error.log"}
    assert {str(path) for path in hosts["db"].allowed_logs} == {
        "/var/log/postgresql/postgresql.log"
    }


def test_per_host_thresholds_load_with_safe_defaults(tmp_path: Path) -> None:
    config = tmp_path / "hosts.toml"
    config.write_text(
        "[hosts.web]\n"
        + 'hostname = "web.internal"\n'
        + 'username = "reader"\n'
        + connection_settings(tmp_path)
        + 'allowed_logs = ["/var/log/syslog"]\n\n'
        "[hosts.web.thresholds]\n"
        "cpu_percent = 75.5\n"
        "memory_percent = 82\n",
        encoding="utf-8",
    )
    host = load_hosts(config)["web"]
    assert host.thresholds == ResourceThresholds(cpu_percent=75.5, memory_percent=82)


def test_save_hosts_round_trips_atomically(tmp_path: Path) -> None:
    config = tmp_path / "hosts.toml"
    host = HostConfig(
        name="web.prod",
        hostname="web.internal",
        username="reader",
        known_hosts=str(tmp_path / "known_hosts"),
        client_keys=(tmp_path / "id_readonly",),
        allowed_logs=frozenset({PurePosixPath("/var/log/syslog")}),
        thresholds=ResourceThresholds(70, 80),
    )
    save_hosts(config, {host.name: host})

    assert load_hosts(config) == {host.name: host}
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "bad;name"},
        {"hostname": "host\nreboot"},
        {"username": "reader;root"},
        {"known_hosts": None},
        {"client_keys": ()},
        {"allowed_logs": frozenset()},
        {"thresholds": ResourceThresholds(101, 90)},
    ],
)
def test_save_rejects_malformed_or_incomplete_hosts(tmp_path: Path, changes) -> None:
    values = {
        "name": "test",
        "hostname": "localhost",
        "username": "reader",
        "known_hosts": str(tmp_path / "known_hosts"),
        "client_keys": (tmp_path / "id_readonly",),
        "allowed_logs": frozenset({PurePosixPath("/var/log/syslog")}),
        "thresholds": ResourceThresholds(),
    }
    values.update(changes)
    host = HostConfig(**values)
    with pytest.raises(ConfigError):
        save_hosts(tmp_path / "hosts.toml", {host.name: host})


def test_host_log_allowlists_are_isolated(tmp_path: Path) -> None:
    web = HostConfig(
        "web",
        "web.internal",
        "reader",
        str(tmp_path / "known_hosts"),
        (tmp_path / "id_readonly",),
        frozenset({PurePosixPath("/var/log/nginx/error.log")}),
    )
    database = HostConfig(
        "db",
        "db.internal",
        "reader",
        str(tmp_path / "known_hosts"),
        (tmp_path / "id_readonly",),
        frozenset({PurePosixPath("/var/log/postgresql/postgresql.log")}),
    )
    policy = ReadOnlyCommandPolicy({"web": web, "db": database})

    assert policy.read_log("web", "/var/log/nginx/error.log", "tail", 10)[-1] == (
        "/var/log/nginx/error.log"
    )
    with pytest.raises(PolicyError, match="allowlisted"):
        policy.read_log("db", "/var/log/nginx/error.log", "tail", 10)
