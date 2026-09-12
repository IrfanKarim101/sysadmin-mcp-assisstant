from pathlib import Path, PurePosixPath

import pytest

from sysadmin_mcp.config import ConfigError, HostConfig, ManagedFilePolicy, save_hosts, load_hosts
from sysadmin_mcp.managed_files import ManagedFileDenied, ManagedFilePlanner


def host(*policies: ManagedFilePolicy) -> HostConfig:
    return HostConfig(
        name="lab", hostname="192.0.2.10", username="reader",
        known_hosts="C:/known_hosts", client_keys=(Path("C:/id"),),
        allowed_logs=frozenset({PurePosixPath("/var/log/syslog")}),
        environment="disposable_lab", managed_files=policies,
    )


def policies():
    return (
        ManagedFilePolicy("nginx-site", PurePosixPath("/etc/nginx"),
                          PurePosixPath("conf.d/app.conf"), "nginx"),
        ManagedFilePolicy("worker-unit", PurePosixPath("/etc/systemd/system"),
                          PurePosixPath("worker.service"), "systemd", mode="0640"),
    )


def test_named_policy_produces_bounded_atomic_plan():
    planner = ManagedFilePlanner({"lab": host(*policies())})
    result = planner.preview("lab", "nginx-site", "server {\n  listen 8080;\n}")
    assert result["resolved_path"] == "/etc/nginx/conf.d/app.conf"
    assert result["diff"].startswith("--- nginx-site:before")
    assert result["atomic_steps"][-2:] == ["atomic_rename", "fsync_parent_directory"]
    assert result["symlink_policy"].startswith("O_NOFOLLOW")
    assert result["remote_mutation"] is False


@pytest.mark.parametrize("path_id", ["/etc/passwd", "../passwd", "nginx-site;reboot", "$(id)"])
def test_raw_or_injection_shaped_paths_are_never_resolved(path_id):
    planner = ManagedFilePlanner({"lab": host(*policies())})
    with pytest.raises(ManagedFileDenied, match="not allowlisted"):
        planner.preview("lab", path_id, "x=1")


@pytest.mark.parametrize("policy", [
    ManagedFilePolicy("bad", PurePosixPath("/proc"), PurePosixPath("x")),
    ManagedFilePolicy("bad", PurePosixPath("/etc"), PurePosixPath("../shadow")),
    ManagedFilePolicy("bad", PurePosixPath("/etc"), PurePosixPath("x"), mode="0777"),
    ManagedFilePolicy("bad", PurePosixPath("/etc"), PurePosixPath("x"), owner="root;id"),
])
def test_device_traversal_and_unsafe_metadata_policy_is_rejected(tmp_path, policy):
    with pytest.raises(ConfigError, match="managed file"):
        save_hosts(tmp_path / "hosts.toml", {"lab": host(policy)})


def test_encoding_size_and_validator_failures_are_rejected():
    limited = ManagedFilePolicy("small", PurePosixPath("/etc/evesdropctl"),
                                PurePosixPath("small.conf"), max_bytes=5)
    planner = ManagedFilePlanner({"lab": host(*policies(), limited)})
    with pytest.raises(ManagedFileDenied, match="limit"):
        planner.preview("lab", "small", "12345")  # normalized newline also counts
    with pytest.raises(ManagedFileDenied, match="UTF-8"):
        planner.preview("lab", "nginx-site", "\ud800")
    with pytest.raises(ManagedFileDenied, match="Nginx"):
        planner.preview("lab", "nginx-site", "include /tmp/evil;")
    with pytest.raises(ManagedFileDenied, match="systemd"):
        planner.preview("lab", "worker-unit", "ExecStart=/bin/true")


def test_managed_policy_round_trips_through_toml(tmp_path):
    path = tmp_path / "hosts.toml"
    expected = host(*policies())
    save_hosts(path, {"lab": expected})
    assert load_hosts(path)["lab"].managed_files == expected.managed_files
