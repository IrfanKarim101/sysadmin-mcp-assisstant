import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from sysadmin_mcp.forced_command import CommandDenied
from sysadmin_mcp.privileged_helper import authorize_action


def policy(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text('[policy]\nallowed_logs=["/var/log/syslog"]\nrestart_services=["nginx.service"]\n')
    real_stat = path.stat()
    secure = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
    monkeypatch.setattr("sysadmin_mcp.forced_command.os.stat", lambda target, follow_symlinks: secure)
    assert real_stat.st_size > 0
    return path


def test_helper_maps_typed_action_to_one_fixed_absolute_command(tmp_path: Path, monkeypatch):
    path = policy(tmp_path, monkeypatch)
    assert authorize_action(("restart-service", "nginx.service"), str(path)) == (
        "/usr/bin/systemctl", "restart", "nginx.service"
    )


def test_helper_maps_backup_id_to_root_owned_executable(tmp_path: Path, monkeypatch):
    path = tmp_path / "policy.toml"
    path.write_text(
        '[policy]\nallowed_logs=["/var/log/syslog"]\n'
        '[policy.backup_jobs]\ndatabase-dump="/root/database-dump.sh"\n'
    )
    secure_policy = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
    secure_script = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0)
    monkeypatch.setattr(
        "sysadmin_mcp.forced_command.os.stat",
        lambda target, follow_symlinks: secure_policy,
    )
    monkeypatch.setattr(
        "sysadmin_mcp.privileged_helper.os.stat",
        lambda target, follow_symlinks: secure_script,
    )
    assert authorize_action(("run-backup", "database-dump"), str(path)) == (
        "/root/database-dump.sh",
    )


@pytest.mark.parametrize("job", ["../dump", "database-dump;id", "$(id)", "missing"])
def test_helper_rejects_unapproved_backup_job(tmp_path: Path, monkeypatch, job):
    path = policy(tmp_path, monkeypatch)
    with pytest.raises(CommandDenied):
        authorize_action(("run-backup", job), str(path))


@pytest.mark.parametrize("argv", [
    (), ("restart-service",), ("restart-service", "ssh.service"),
    ("restart-service", "nginx.service;reboot"), ("shell", "nginx.service"),
    ("restart-service", "nginx.service", "extra"),
])
def test_helper_rejects_unknown_injection_and_oversized_shapes(tmp_path: Path, monkeypatch, argv):
    path = policy(tmp_path, monkeypatch)
    with pytest.raises(CommandDenied):
        authorize_action(argv, str(path))
