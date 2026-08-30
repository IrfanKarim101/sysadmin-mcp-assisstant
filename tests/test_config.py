from pathlib import Path

import pytest

from sysadmin_mcp.config import load_hosts


@pytest.mark.parametrize("path", ["../etc/shadow", "/var/log/../shadow"])
def test_config_rejects_unsafe_allowlist_paths(tmp_path: Path, path: str) -> None:
    config = tmp_path / "hosts.toml"
    config.write_text(
        "[hosts.test]\n"
        'hostname = "localhost"\n'
        'username = "reader"\n'
        f'allowed_logs = ["{path}"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsafe allowed log path"):
        load_hosts(config)


def test_config_drives_per_host_log_allowlists(tmp_path: Path) -> None:
    config = tmp_path / "hosts.toml"
    config.write_text(
        "[hosts.web]\n"
        'hostname = "web.internal"\n'
        'username = "reader"\n'
        'allowed_logs = ["/var/log/nginx/error.log"]\n\n'
        "[hosts.db]\n"
        'hostname = "db.internal"\n'
        'username = "reader"\n'
        'allowed_logs = ["/var/log/postgresql/postgresql.log"]\n',
        encoding="utf-8",
    )
    hosts = load_hosts(config)
    assert {str(path) for path in hosts["web"].allowed_logs} == {"/var/log/nginx/error.log"}
    assert {str(path) for path in hosts["db"].allowed_logs} == {
        "/var/log/postgresql/postgresql.log"
    }
