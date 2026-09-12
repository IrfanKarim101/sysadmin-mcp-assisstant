from pathlib import Path, PurePosixPath

import pytest

from sysadmin_mcp.config import ConfigError, HostConfig, PackagePolicy, load_hosts, save_hosts
from sysadmin_mcp.packages import PackageDenied, PackagePlanner


def host(*packages: PackagePolicy) -> HostConfig:
    return HostConfig(
        name="lab", hostname="192.0.2.10", username="reader", known_hosts="C:/known_hosts",
        client_keys=(Path("C:/id"),), allowed_logs=frozenset({PurePosixPath("/var/log/syslog")}),
        environment="disposable_lab", packages=packages,
    )


def nginx(**changes) -> PackagePolicy:
    values = {"id": "web-server", "name": "nginx", "allowed_versions": ("1.24.0-1",),
              "dependencies": ("libpcre2-8-0",), "dependent_services": ("nginx.service",),
              "download_bytes": 1_000_000, "disk_bytes": 3_000_000}
    values.update(changes)
    return PackagePolicy(**values)


def test_package_preview_is_fixed_bounded_and_repository_safe():
    planner = PackagePlanner({"lab": host(nginx())})
    result = planner.preview("update_package", "lab", "web-server", "1.24.0-1")
    assert result["simulation_argv"] == ["apt-get", "--simulate", "--no-remove", "install", "nginx=1.24.0-1"]
    assert result["repository_change"] is False and result["key_change"] is False
    assert result["removals"] == [] and result["lock_check"] == "required"
    assert "service_active=nginx.service" in result["verify"]
    assert result["remote_mutation"] is False


@pytest.mark.parametrize("package_id,version", [
    ("nginx;reboot", "1.24.0-1"), ("/tmp/pkg.deb", "1.24.0-1"),
    ("web-server", "1.24.0-1;id"), ("web-server", "latest"),
])
def test_unapproved_ids_versions_and_injection_shapes_are_denied(package_id, version):
    planner = PackagePlanner({"lab": host(nginx())})
    with pytest.raises(PackageDenied):
        planner.preview("install_package", "lab", package_id, version)


def test_held_package_and_unsupported_action_are_denied():
    planner = PackagePlanner({"lab": host(nginx(held=True))})
    with pytest.raises(PackageDenied, match="held"):
        planner.preview("update_package", "lab", "web-server", None)
    with pytest.raises(PackageDenied, match="Unsupported"):
        planner.preview("remove_package", "lab", "web-server", None)


def test_canary_is_deterministic_and_failure_halts_remaining_hosts():
    rollout = PackagePlanner.rollout([{"host": "vm-b"}, {"host": "vm-a"}, {"host": "vm-c"}])
    assert rollout["canary"] == "vm-a"
    assert rollout["remaining_hosts"] == ["vm-b", "vm-c"]
    assert rollout["failure_action"] == "halt_remaining_hosts"


@pytest.mark.parametrize("policy", [
    nginx(name="nginx;id"), nginx(allowed_versions=()), nginx(allowed_versions=("latest;id",)),
    nginx(download_bytes=2_000_000_001), nginx(dependent_services=("nginx;id",)),
])
def test_unsafe_or_oversized_package_policy_is_rejected(tmp_path, policy):
    with pytest.raises(ConfigError, match="package policy"):
        save_hosts(tmp_path / "hosts.toml", {"lab": host(policy)})


def test_package_policy_round_trips(tmp_path):
    path = tmp_path / "hosts.toml"
    expected = host(nginx(reboot_required=True))
    save_hosts(path, {"lab": expected})
    assert load_hosts(path)["lab"].packages == expected.packages
