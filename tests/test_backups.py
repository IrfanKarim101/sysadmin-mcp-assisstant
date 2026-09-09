from pathlib import Path, PurePosixPath

import pytest

from sysadmin_mcp.audit import SQLiteAuditLog
from sysadmin_mcp.backups import BackupDenied, BackupService
from sysadmin_mcp.config import HostConfig
from sysadmin_mcp.models import CommandResult


def host() -> HostConfig:
    return HostConfig(
        name="db-01", hostname="192.0.2.10", username="reader",
        known_hosts="/tmp/known_hosts", client_keys=(Path("/tmp/key"),),
        allowed_logs=frozenset({PurePosixPath("/var/log/syslog")}),
        backup_jobs=frozenset({"database-dump"}),
    )


class FakeTransport:
    def __init__(self) -> None:
        self.commands = []

    async def run(self, target, command):
        self.commands.append(command)
        return CommandResult(command, "dump completed\n", "", 0)


@pytest.mark.asyncio
async def test_backup_uses_only_typed_job_and_one_use_session_bound_approval(tmp_path: Path):
    transport = FakeTransport()
    service = BackupService({"db-01": host()}, transport, SQLiteAuditLog(tmp_path / "audit.db"))
    preview = service.preview("admin", "session-a", "db-01", "database-dump")

    with pytest.raises(BackupDenied, match="session"):
        await service.execute(preview["approval_token"], "admin", "session-b")
    assert transport.commands == []

    preview = service.preview("admin", "session-a", "db-01", "database-dump")
    result = await service.execute(preview["approval_token"], "admin", "session-a")
    assert result["verified"] is True
    assert transport.commands == [(
        "sudo", "-n", "/usr/local/bin/sysadmin-remediate", "run-backup", "database-dump"
    )]
    with pytest.raises(BackupDenied, match="already used"):
        await service.execute(preview["approval_token"], "admin", "session-a")


@pytest.mark.parametrize("job", [
    "../database-dump", "database-dump;reboot", "$(id)", "database-dump extra", "x" * 65,
])
def test_backup_rejects_unknown_and_injection_shaped_jobs(tmp_path: Path, job: str):
    service = BackupService(
        {"db-01": host()}, FakeTransport(), SQLiteAuditLog(tmp_path / "audit.db")
    )
    with pytest.raises(BackupDenied, match="allowlisted"):
        service.preview("admin", "session", "db-01", job)
