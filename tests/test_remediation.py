from pathlib import Path, PurePosixPath

import pytest

from sysadmin_mcp.audit import SQLiteAuditLog
from sysadmin_mcp.config import HostConfig
from sysadmin_mcp.models import CommandResult
from sysadmin_mcp.remediation import RemediationDenied, RemediationService


class FakeTransport:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    async def run(self, host, argv):
        command = tuple(argv)
        self.commands.append(command)
        return CommandResult(command, "ActiveState=active\nSubState=running\n", "", 0)


def host() -> HostConfig:
    return HostConfig(
        name="web-01", hostname="192.0.2.10", username="sentinel",
        known_hosts="C:/known_hosts", client_keys=(), password_env="SSH_PASSWORD_WEB",
        allowed_logs=frozenset({PurePosixPath("/var/log/syslog")}),
        restart_services=frozenset({"nginx.service"}),
    )


@pytest.mark.asyncio
async def test_restart_requires_allowlist_and_never_accepts_command_text(tmp_path: Path):
    transport = FakeTransport()
    service = RemediationService({"web-01": host()}, transport, SQLiteAuditLog(tmp_path / "audit.db"))
    for value in ("nginx.service; reboot", "../../bin/sh", "ssh.service"):
        with pytest.raises(RemediationDenied):
            await service.preview_restart("admin", "session", "web-01", value)
    assert transport.commands == []


@pytest.mark.asyncio
async def test_approval_is_session_bound_one_use_and_post_verified(tmp_path: Path):
    transport = FakeTransport()
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    service = RemediationService({"web-01": host()}, transport, audit)
    preview = await service.preview_restart("admin", "session-a", "web-01", "nginx.service")
    with pytest.raises(RemediationDenied, match="session"):
        await service.execute_restart(preview["approval_token"], "admin", "session-b")
    # A theft attempt consumes the token, preventing later replay by either session.
    with pytest.raises(RemediationDenied, match="already used"):
        await service.execute_restart(preview["approval_token"], "admin", "session-a")
    preview = await service.preview_restart("admin", "session-a", "web-01", "nginx.service")
    result = await service.execute_restart(preview["approval_token"], "admin", "session-a")
    assert result["verified"] is True
    assert transport.commands[-2:] == [
        ("systemctl", "restart", "nginx.service"),
        ("systemctl", "show", "nginx.service", "--no-pager",
         "--property=ActiveState,SubState,Result,ExecMainStatus"),
    ]
    with pytest.raises(RemediationDenied, match="already used"):
        await service.execute_restart(preview["approval_token"], "admin", "session-a")
    assert [row.status for row in audit.recent(2)] == ["success", "attempted"]


@pytest.mark.asyncio
async def test_expired_approval_cannot_execute(tmp_path: Path):
    now = [10.0]
    service = RemediationService(
        {"web-01": host()}, FakeTransport(), SQLiteAuditLog(tmp_path / "audit.db"),
        clock=lambda: now[0],
    )
    preview = await service.preview_restart("admin", "session", "web-01", "nginx.service")
    now[0] += 121
    with pytest.raises(RemediationDenied, match="expired"):
        await service.execute_restart(preview["approval_token"], "admin", "session")
