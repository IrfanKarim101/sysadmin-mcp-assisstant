from pathlib import Path

import pytest

from sysadmin_mcp.config import load_hosts
from sysadmin_mcp.host_config_cli import main


def add_arguments(config: Path, name: str = "web") -> list[str]:
    return [
        "--config",
        str(config),
        "add",
        name,
        "--hostname",
        f"{name}.internal",
        "--username",
        "reader",
        "--known-hosts",
        str(config.parent / "known_hosts"),
        "--client-key",
        str(config.parent / "id_readonly"),
        "--allowed-log",
        "/var/log/syslog",
        "--cpu-threshold",
        "75",
        "--memory-threshold",
        "80",
    ]


def test_cli_add_list_and_remove_preserves_other_hosts(
    tmp_path: Path, capsys
) -> None:
    config = tmp_path / "hosts.toml"
    assert main(add_arguments(config, "web")) == 0
    assert main(add_arguments(config, "db")) == 0
    hosts = load_hosts(config)
    assert set(hosts) == {"web", "db"}
    assert hosts["web"].thresholds.cpu_percent == 75

    assert main(["--config", str(config), "list"]) == 0
    listing = capsys.readouterr().out
    assert "reader@web.internal" in listing
    assert "id_readonly" not in listing

    assert main(["--config", str(config), "remove", "web"]) == 0
    assert set(load_hosts(config)) == {"db"}


def test_cli_refuses_accidental_duplicate_without_replace(tmp_path: Path) -> None:
    config = tmp_path / "hosts.toml"
    main(add_arguments(config))
    with pytest.raises(SystemExit) as error:
        main(add_arguments(config))
    assert error.value.code == 2
    assert set(load_hosts(config)) == {"web"}


def test_cli_rejects_unsafe_values_before_writing(tmp_path: Path) -> None:
    config = tmp_path / "hosts.toml"
    arguments = add_arguments(config, "bad;name")
    with pytest.raises(SystemExit) as error:
        main(arguments)
    assert error.value.code == 2
    assert not config.exists()
