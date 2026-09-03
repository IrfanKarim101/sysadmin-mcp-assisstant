import shlex
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest

from sysadmin_mcp.config import HostConfig
from sysadmin_mcp.forced_command import (
    DEFAULT_BINARIES,
    MAX_COMMAND_LENGTH,
    CommandDenied,
    authorize_command,
    load_allowed_logs,
    validate_policy_file,
)
from sysadmin_mcp.policy import ReadOnlyCommandPolicy

ALLOWED = frozenset({PurePosixPath("/var/log/syslog")})


def authorize(argv: tuple[str, ...]) -> tuple[str, ...]:
    return authorize_command(shlex.join(argv), ALLOWED)


@pytest.mark.parametrize(
    "argv",
    [
        ("ss", "-tulnp"),
        ("netstat", "-tulnp"),
        ("systemctl", "list-units", "--type=service", "--no-pager", "--no-legend"),
        (
            "systemctl",
            "list-units",
            "--type=service",
            "--no-pager",
            "--no-legend",
            "--state=failed",
        ),
        ("top", "-bn1"),
        ("free", "-h"),
        ("vmstat", "1", "2"),
        ("tail", "-n", "500", "/var/log/syslog"),
        ("head", "-n", "1", "/var/log/syslog"),
        ("sed", "-n", "1,100p", "/var/log/syslog"),
        ("grep", "-n", "-m", "100", "--", "x'; touch /tmp/pwned", "/var/log/syslog"),
        ("w", "-h"),
        ("who",),
    ],
)
def test_exact_read_only_commands_are_authorized(argv: tuple[str, ...]) -> None:
    assert authorize(argv) == (DEFAULT_BINARIES[argv[0]], *argv[1:])


@pytest.mark.parametrize(
    "command_text",
    [
        None,
        "",
        "sh",
        "bash -c id",
        "who; touch /tmp/pwned",
        "who && id",
        "who | tee /tmp/pwned",
        "who > /tmp/pwned",
        "$(touch /tmp/pwned)",
        "tail -n 10 /etc/shadow",
        "tail -n 10 ../../etc/shadow",
        "tail -n 501 /var/log/syslog",
        "tail -n 01 /var/log/syslog",
        "cat /var/log/syslog",
        "grep -n error /var/log/syslog",
        "grep -n -m 10 -- error /var/log/syslog extra",
        "systemctl restart ssh",
        "systemctl list-units --type=service --no-pager --no-legend --state=active;reboot",
        "scp -t /tmp/file",
        "sftp-server",
        "'unterminated",
    ],
)
def test_shell_escapes_and_out_of_policy_commands_are_denied(
    command_text: str | None,
) -> None:
    with pytest.raises(CommandDenied):
        authorize_command(command_text, ALLOWED)


def test_oversized_original_command_is_denied() -> None:
    with pytest.raises(CommandDenied, match="too long"):
        authorize_command("x" * (MAX_COMMAND_LENGTH + 1), ALLOWED)


def test_binary_mapping_must_use_an_absolute_path() -> None:
    with pytest.raises(CommandDenied, match="configured safely"):
        authorize_command("who", ALLOWED, {"who": "bin/who"})


def test_os_gate_accepts_every_phase_one_command_shape() -> None:
    host = HostConfig(
        name="test",
        hostname="localhost",
        username="sysadmin-readonly",
        known_hosts=None,
        client_keys=(),
        allowed_logs=ALLOWED,
    )
    policy = ReadOnlyCommandPolicy({"test": host})
    commands = [
        policy.ports(),
        policy.ports(fallback=True),
        policy.services(),
        policy.services("inactive"),
        *policy.resources(),
        policy.read_log("test", "/var/log/syslog", "head", 10),
        policy.read_log("test", "/var/log/syslog", "tail", 10),
        policy.read_log("test", "/var/log/syslog", "cat", 10),
        policy.grep_log("test", "/var/log/syslog", "error", 10),
        *policy.active_users(),
    ]
    for command in commands:
        authorize(command)


def test_policy_file_requires_safe_absolute_logs(tmp_path) -> None:
    policy_file = tmp_path / "policy.toml"
    policy_file.write_text('[policy]\nallowed_logs = ["../etc/shadow"]\n', encoding="utf-8")
    with pytest.raises(CommandDenied, match="unsafe log path"):
        load_allowed_logs(str(policy_file))


def test_os_policy_file_must_be_root_owned_regular_and_not_writable(monkeypatch) -> None:
    secure = SimpleNamespace(st_mode=0o100644, st_uid=0)
    monkeypatch.setattr("os.stat", lambda path, follow_symlinks: secure)
    validate_policy_file("/etc/policy.toml")

    for metadata in (
        SimpleNamespace(st_mode=0o100664, st_uid=0),
        SimpleNamespace(st_mode=0o100644, st_uid=1000),
        SimpleNamespace(st_mode=0o120777, st_uid=0),
    ):
        monkeypatch.setattr("os.stat", lambda path, follow_symlinks, item=metadata: item)
        with pytest.raises(CommandDenied, match="policy"):
            validate_policy_file("/etc/policy.toml")
