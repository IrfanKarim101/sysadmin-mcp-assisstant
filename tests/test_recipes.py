from pathlib import Path, PurePosixPath

import pytest

from sysadmin_mcp.config import HostConfig, ManagedFilePolicy, PackagePolicy, ServicePolicy
from sysadmin_mcp.recipes import AutonomousRecipePlanner, NGINX_RECIPE, RecipeDenied


def host(environment="disposable_lab"):
    return HostConfig(
        name="lab", hostname="192.0.2.10", username="reader",
        known_hosts="C:/known_hosts", client_keys=(Path("C:/id"),),
        allowed_logs=frozenset({PurePosixPath("/var/log/nginx/error.log")}),
        environment=environment,
        managed_files=(ManagedFilePolicy(
            "nginx-site", PurePosixPath("/etc/nginx"),
            PurePosixPath("conf.d/evesdropctl.conf"), validator="nginx",
        ),),
        packages=(PackagePolicy("nginx", "nginx", ("1.24.0-1",)),),
        services=(ServicePolicy(
            "nginx", "nginx.service", ("reload_service", "restart_service"),
            config_path_id="nginx-site",
        ),),
    )


def test_nginx_recipe_expands_only_to_fixed_typed_actions():
    actions = AutonomousRecipePlanner({"lab": host()}).plan(
        NGINX_RECIPE, "lab", "server { listen 80; }\n", "1.24.0-1"
    )
    assert [item.action for item in actions] == [
        "install_package", "write_managed_file", "reload_service"
    ]
    assert [item.target for item in actions] == ["nginx", "nginx-site", "nginx"]
    assert actions[0].version == "1.24.0-1"
    assert actions[1].value == "server { listen 80; }\n"


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_recipe_denies_non_lab_environments(environment):
    with pytest.raises(RecipeDenied, match="development or disposable"):
        AutonomousRecipePlanner({"lab": host(environment)}).plan(
            NGINX_RECIPE, "lab", "server { listen 80; }\n"
        )


def test_recipe_denies_unknown_recipe_and_incomplete_policy():
    planner = AutonomousRecipePlanner({"lab": host()})
    with pytest.raises(RecipeDenied, match="Unknown"):
        planner.plan("shell@1", "lab", "x")
    incomplete = host().__class__(**{**host().__dict__, "packages": ()})
    with pytest.raises(RecipeDenied, match="missing"):
        AutonomousRecipePlanner({"lab": incomplete}).plan(
            NGINX_RECIPE, "lab", "server { listen 80; }\n"
        )
