import json
from pathlib import Path

from sysadmin_mcp.preflight import check_local_prerequisites, main


def write_config(path: Path, known_hosts: Path, key: Path) -> None:
    path.write_text(
        "[hosts.test]\n"
        'hostname = "test.internal"\n'
        'username = "reader"\n'
        f"known_hosts = {json.dumps(str(known_hosts))}\n"
        f"client_keys = [{json.dumps(str(key))}]\n"
        'allowed_logs = ["/var/log/syslog"]\n',
        encoding="utf-8",
    )


def test_preflight_passes_ready_local_files(tmp_path: Path, capsys) -> None:
    config = tmp_path / "hosts.toml"
    known_hosts = tmp_path / "known_hosts"
    key = tmp_path / "id_readonly"
    audit_directory = tmp_path / "data"
    known_hosts.write_text("host key", encoding="utf-8")
    key.write_text("private key", encoding="utf-8")
    key.chmod(0o600)
    audit_directory.mkdir()
    write_config(config, known_hosts, key)

    assert check_local_prerequisites(config, audit_directory / "audit.db") == []
    assert main(["--config", str(config), "--audit-db", str(audit_directory / "audit.db")]) == 0
    assert "Preflight passed" in capsys.readouterr().out


def test_preflight_reports_missing_files_without_secret_paths(tmp_path: Path) -> None:
    config = tmp_path / "hosts.toml"
    write_config(config, tmp_path / "missing-known", tmp_path / "missing-key")

    problems = check_local_prerequisites(config, tmp_path / "missing-data" / "audit.db")
    assert len(problems) == 3
    assert any("known_hosts file does not exist" in problem for problem in problems)
    assert any("client key does not exist" in problem for problem in problems)
    assert all("missing-key" not in problem for problem in problems)
