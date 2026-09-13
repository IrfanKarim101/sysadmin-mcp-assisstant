from pathlib import Path, PurePosixPath

import pytest

from sysadmin_mcp.config import ConfigError, HostConfig, ManagedFilePolicy, ServicePolicy, load_hosts, save_hosts
from sysadmin_mcp.services import ServiceDenied, ServicePlanner


def host(*services: ServicePolicy) -> HostConfig:
    return HostConfig(
        name="lab", hostname="192.0.2.10", username="reader", known_hosts="C:/known_hosts",
        client_keys=(Path("C:/id"),),
        allowed_logs=frozenset({PurePosixPath("/var/log/nginx/error.log")}),
        environment="disposable_lab",
        managed_files=(ManagedFilePolicy("nginx-site", PurePosixPath("/etc/nginx"),
                                         PurePosixPath("conf.d/app.conf"), "nginx"),),
        services=services,
    )


def nginx(**changes) -> ServicePolicy:
    values = {"id": "web", "unit": "nginx.service",
              "actions": ("reload_service", "restart_service"),
              "config_path_id": "nginx-site", "listen_ports": (80, 443),
              "health_path": "/health", "log_path": PurePosixPath("/var/log/nginx/error.log"),
              "max_log_lines": 50, "material_restart": True}
    values.update(changes)
    return ServicePolicy(**values)


def test_reload_requires_validation_and_has_no_expected_downtime():
    planner = ServicePlanner({"lab": host(nginx())})
    with pytest.raises(ServiceDenied, match="requires"):
        planner.preview("reload_service", "lab", "web", ())
    result = planner.preview("reload_service", "lab", "web", ("nginx-site",))
    assert result["configuration_validated"] is True
    assert result["impact"].startswith("none expected")
    assert result["helper_argv"][-2:] == ["reload", "web"]
    assert result["remote_mutation"] is False


def test_restart_is_material_and_verifies_state_ports_logs_and_health():
    planner = ServicePlanner({"lab": host(nginx())})
    result = planner.preview("restart_service", "lab", "web", ("nginx-site",))
    assert result["material_approval_required"] is True
    assert {item["type"] for item in result["verification_checks"]} == {
        "systemd_state", "listening_port", "bounded_log", "http_health"
    }
    assert next(x for x in result["verification_checks"] if x["type"] == "bounded_log")["lines"] == 50
    assert result["verification_rule"].startswith("all checks")


def test_command_success_never_substitutes_for_health_and_failure_rolls_back():
    planner = ServicePlanner({"lab": host(nginx(config_path_id=None))})
    plan = planner.preview("restart_service", "lab", "web", ())
    failed = planner.evaluate(plan, [{"passed": True}])
    assert failed == {"healthy": False, "command_success_is_sufficient": False,
                      "decision": "automatic_rollback", "checks_passed": 1,
                      "checks_expected": 5}
    passed = planner.evaluate(plan, [{"passed": True}] * 5)
    assert passed["healthy"] is True and passed["decision"] == "accept"


@pytest.mark.parametrize("service_id", ["web;reboot", "../web", "$(id)", "/tmp/unit"])
def test_injection_shaped_service_ids_are_denied(service_id):
    planner = ServicePlanner({"lab": host(nginx(config_path_id=None))})
    with pytest.raises(ServiceDenied, match="not allowlisted"):
        planner.preview("restart_service", "lab", service_id, ())


@pytest.mark.parametrize("policy", [
    nginx(unit="nginx;id"), nginx(actions=("stop_service",)),
    nginx(listen_ports=(0,)), nginx(health_path="http://evil.example/"),
    nginx(log_path=PurePosixPath("/etc/shadow")), nginx(max_log_lines=201),
])
def test_unsafe_service_policy_is_rejected(tmp_path, policy):
    with pytest.raises(ConfigError, match="service policy"):
        save_hosts(tmp_path / "hosts.toml", {"lab": host(policy)})


def test_service_policy_round_trips(tmp_path):
    path = tmp_path / "hosts.toml"; expected = host(nginx())
    save_hosts(path, {"lab": expected})
    assert load_hosts(path)["lab"].services == expected.services
