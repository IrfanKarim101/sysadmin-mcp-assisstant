"""Typed package lifecycle previews with fixed, non-executing builders."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .config import HostConfig, PackagePolicy


class PackageDenied(ValueError):
    pass


class PackagePlanner:
    def __init__(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    def replace_hosts(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    def policies(self) -> list[dict[str, object]]:
        return [{"host": host.name, "manager": host.package_manager,
                 "packages": [_view(item) for item in host.packages]}
                for host in self._hosts.values()]

    def preview(self, action: str, host: str, package_id: str,
                version: str | None) -> dict[str, object]:
        if action not in {"install_package", "update_package"}:
            raise PackageDenied("Unsupported package action")
        target, policy = self._policy(host, package_id)
        selected = version or policy.allowed_versions[-1]
        if selected not in policy.allowed_versions:
            raise PackageDenied("Package version is not allowlisted for this host")
        if policy.held:
            raise PackageDenied("Package is held by host policy")
        spec = f"{policy.name}={selected}"
        simulate = ("apt-get", "--simulate", "--no-remove", "install", spec)
        apply = ("sudo", "-n", "/usr/local/bin/evesdropctl-package", action, package_id, selected)
        return {
            "package_id": package_id, "package_name": policy.name,
            "requested_version": selected, "before_version": "simulated-current",
            "manager": target.package_manager, "approved_repositories_only": True,
            "repository_change": False, "key_change": False,
            "dependencies": list(policy.dependencies), "removals": [],
            "download_bytes": policy.download_bytes, "disk_bytes": policy.disk_bytes,
            "lock_check": "required", "held": False,
            "reboot_required": policy.reboot_required,
            "dependent_services": list(policy.dependent_services),
            "simulation_argv": list(simulate), "host_helper_argv": list(apply),
            "verify": [f"installed_version={selected}",
                       *[f"service_active={item}" for item in policy.dependent_services]],
            "rollback_limitation": "prior version restore requires it to remain in approved repositories",
            "remote_mutation": False,
        }

    @staticmethod
    def rollout(plans: Sequence[Mapping[str, object]]) -> dict[str, object]:
        hosts = sorted({str(item["host"]) for item in plans})
        return {"canary": hosts[0] if hosts else None, "remaining_hosts": hosts[1:],
                "continue_only_if": ["no_removals", "dependency_set_unchanged",
                                     "version_verified", "dependent_services_healthy"],
                "failure_action": "halt_remaining_hosts"}

    def _policy(self, host: str, package_id: str) -> tuple[HostConfig, PackagePolicy]:
        try:
            target = self._hosts[host]
        except KeyError as error:
            raise PackageDenied("Unknown or unapproved host") from error
        matches = [item for item in target.packages if item.id == package_id]
        if len(matches) != 1:
            raise PackageDenied("Package ID is not allowlisted for this host")
        if target.package_manager != "apt":
            raise PackageDenied("Host package manager is unsupported")
        return target, matches[0]


def _view(item: PackagePolicy) -> dict[str, object]:
    return {"id": item.id, "name": item.name, "allowed_versions": list(item.allowed_versions),
            "dependencies": list(item.dependencies),
            "dependent_services": list(item.dependent_services),
            "download_bytes": item.download_bytes, "disk_bytes": item.disk_bytes,
            "reboot_required": item.reboot_required, "held": item.held}
