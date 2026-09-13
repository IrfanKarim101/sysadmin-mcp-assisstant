"""Typed service activation plans with deterministic verification and rollback rules."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .config import HostConfig, ServicePolicy


class ServiceDenied(ValueError):
    pass


class ServicePlanner:
    def __init__(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    def replace_hosts(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    def policies(self) -> list[dict[str, object]]:
        return [{"host": host.name, "services": [_view(item) for item in host.services]}
                for host in self._hosts.values()]

    def preview(self, action: str, host: str, service_id: str,
                validated_files: Sequence[str]) -> dict[str, object]:
        target, policy = self._policy(host, service_id)
        if action not in policy.actions:
            raise ServiceDenied("Service action is not allowlisted for this host")
        if action in {"reload_service", "restart_service"} and policy.config_path_id:
            if policy.config_path_id not in validated_files:
                raise ServiceDenied("Service activation requires its managed configuration validation")
        lifecycle = action.removesuffix("_service").replace("_", "-")
        helper = ("sudo", "-n", "/usr/local/bin/evesdropctl-service",
                  lifecycle, policy.id)
        downtime = (
            "none expected; existing process remains active" if action == "reload_service"
            else "brief interruption expected" if action == "restart_service"
            else "service becomes unavailable" if action == "disable_service"
            else "none expected"
        )
        expected_active = action != "disable_service"
        checks: list[dict[str, object]] = [
            {"type": "systemd_state", "unit": policy.unit,
             "expected": "active" if expected_active else "inactive"},
            *[{"type": "listening_port", "port": port, "expected": expected_active}
              for port in policy.listen_ports],
        ]
        if policy.log_path:
            checks.append({"type": "bounded_log", "path": str(policy.log_path),
                           "lines": policy.max_log_lines, "treat_as_untrusted": True})
        if policy.health_path and expected_active:
            checks.append({"type": "http_health", "scheme": "http", "host": "127.0.0.1",
                           "path": policy.health_path, "expected_status": 200})
        return {
            "service_id": policy.id, "unit": policy.unit, "action": action,
            "helper_argv": list(helper), "config_path_id": policy.config_path_id,
            "configuration_validated": policy.config_path_id is None
                                       or policy.config_path_id in validated_files,
            "impact": downtime,
            "material_approval_required": action == "restart_service" and policy.material_restart,
            "verification_checks": checks,
            "verification_rule": "all checks must pass; command exit status alone is insufficient",
            "clear_failure_action": "automatic_rollback",
            "ambiguous_failure_action": "pause_for_operator",
            "remote_mutation": False,
        }

    @staticmethod
    def evaluate(plan: Mapping[str, object], results: Sequence[Mapping[str, object]]) -> dict[str, object]:
        expected = len(plan["verification_checks"])  # type: ignore[arg-type]
        passed = len(results) == expected and all(item.get("passed") is True for item in results)
        return {"healthy": passed, "command_success_is_sufficient": False,
                "decision": "accept" if passed else "automatic_rollback",
                "checks_passed": sum(item.get("passed") is True for item in results),
                "checks_expected": expected}

    def _policy(self, host: str, service_id: str) -> tuple[HostConfig, ServicePolicy]:
        try:
            target = self._hosts[host]
        except KeyError as error:
            raise ServiceDenied("Unknown or unapproved host") from error
        matches = [item for item in target.services if item.id == service_id]
        if len(matches) != 1:
            raise ServiceDenied("Service ID is not allowlisted for this host")
        return target, matches[0]


def _view(item: ServicePolicy) -> dict[str, object]:
    return {"id": item.id, "unit": item.unit, "actions": list(item.actions),
            "config_path_id": item.config_path_id, "listen_ports": list(item.listen_ports),
            "health_path": item.health_path, "log_path": str(item.log_path) if item.log_path else None,
            "max_log_lines": item.max_log_lines, "material_restart": item.material_restart}
