"""Versioned autonomous recipes expanded only into existing typed actions."""

from __future__ import annotations

from collections.abc import Mapping

from .changes import ChangeAction
from .config import HostConfig

NGINX_RECIPE = "nginx_install_configure@1"


class RecipeDenied(ValueError):
    pass


class AutonomousRecipePlanner:
    def __init__(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    def replace_hosts(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    @staticmethod
    def recipes() -> list[dict[str, object]]:
        return [{
            "id": NGINX_RECIPE, "version": 1,
            "required_capabilities": ["managed_files", "packages", "services"],
            "live_execution": False,
        }]

    def plan(self, recipe_id: str, host: str, config_content: str,
             package_version: str | None = None) -> list[ChangeAction]:
        if recipe_id != NGINX_RECIPE:
            raise RecipeDenied("Unknown autonomous recipe")
        try:
            target = self._hosts[host]
        except KeyError as error:
            raise RecipeDenied("Unknown or unapproved host") from error
        if target.environment not in {"development", "disposable_lab"}:
            raise RecipeDenied("Autonomous recipes require a development or disposable-lab host")
        package = next((item for item in target.packages if item.id == "nginx"), None)
        managed_file = next((item for item in target.managed_files if item.id == "nginx-site"), None)
        service = next((item for item in target.services if item.id == "nginx"), None)
        if package is None or managed_file is None or service is None:
            raise RecipeDenied("Host is missing the reviewed Nginx recipe policy")
        if managed_file.validator != "nginx" or service.config_path_id != managed_file.id:
            raise RecipeDenied("Nginx file and service policy are not safely linked")
        activation = "reload_service" if "reload_service" in service.actions else "restart_service"
        if activation not in service.actions:
            raise RecipeDenied("Nginx service has no approved activation action")
        return [
            ChangeAction(action="install_package", host=host, target=package.id,
                         version=package_version),
            ChangeAction(action="write_managed_file", host=host, target=managed_file.id,
                         value=config_content),
            ChangeAction(action=activation, host=host, target=service.id),
        ]
