from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

import pytest
from pydantic import ValidationError

from sysadmin_mcp.audit import SQLiteAuditLog
from sysadmin_mcp.authority import AuthorityDenied, AuthorityService
from sysadmin_mcp.changes import ChangeAction, ChangeDenied, ChangeTransactionService
from sysadmin_mcp.config import HostConfig, ManagedFilePolicy, PackagePolicy, ServicePolicy
from sysadmin_mcp.managed_files import ManagedFilePlanner
from sysadmin_mcp.packages import PackagePlanner
from sysadmin_mcp.services import ServicePlanner


def host() -> HostConfig:
    return HostConfig(
        name="lab", hostname="192.0.2.10", username="reader",
        known_hosts="C:/known_hosts", client_keys=(Path("C:/id"),),
        allowed_logs=frozenset({PurePosixPath("/var/log/syslog")}),
        environment="disposable_lab",
        managed_files=(ManagedFilePolicy(
            id="app-config", root=PurePosixPath("/etc/evesdropctl"),
            relative_path=PurePosixPath("app.conf"),
        ),),
        packages=(PackagePolicy("nginx", "nginx", ("1.24.0-1",),
                                dependent_services=("nginx.service",)),),
        services=(ServicePolicy("nginx", "nginx.service", ("restart_service",)),),
    )


def services(tmp_path, now=None):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    authority = AuthorityService({"lab": host()}, audit, now=now)
    authority.arm(
        mode="guided", username="admin", session_id="session-a", hosts=["lab"],
        capabilities=["managed_files", "packages", "services", "backups"],
        duration_minutes=15, action_budget=5, concurrency=1,
    )
    return authority, ChangeTransactionService(
        audit.path, authority, audit, now=now,
        managed_files=ManagedFilePlanner({"lab": host()}),
        packages=PackagePlanner({"lab": host()}),
        services=ServicePlanner({"lab": host()}),
    )


def test_transaction_is_deterministic_single_use_and_never_mutates_remote(tmp_path):
    authority, changes = services(tmp_path)
    action = ChangeAction(action="restart_service", host="lab", target="nginx")
    created = changes.create("admin", "session-a", "Restart web", [action])
    first = changes.preview(created["id"], "admin", "session-a")
    second = changes.preview(created["id"], "admin", "session-a")
    assert first["diff_hash"] == second["diff_hash"]
    approved = changes.approve(created["id"], "admin", "session-a")
    assert approved["approval_expires_at"] is not None
    assert approved["rollback_available"] is True
    result = changes.simulate(created["id"], approved["approval_token"], "admin", "session-a")
    assert result["state"] == "verifying"
    assert result["approval_expires_at"] is None
    assert result["rollback_available"] is True
    assert all(event["remote_mutation"] is False for event in result["evidence"])
    assert authority.current()["actions_used"] == 1
    with pytest.raises(ChangeDenied, match="already used"):
        changes.simulate(created["id"], approved["approval_token"], "admin", "session-a")
    accepted = changes.accept(created["id"], "admin", "session-a")
    assert accepted["state"] == "accepted"
    assert accepted["rollback_available"] is False


@pytest.mark.parametrize("bad", [
    {"action": "shell", "host": "lab", "target": "id"},
    {"action": "restart_service", "host": "lab; reboot", "target": "nginx"},
    {"action": "restart_service", "host": "lab", "target": "nginx;reboot"},
    {"action": "restart_service", "host": "lab", "target": "$(reboot)"},
    {"action": "install_package", "host": "lab", "target": "nginx", "value": "ignored"},
])
def test_injection_shaped_or_untyped_actions_are_rejected(bad):
    with pytest.raises(ValidationError):
        ChangeAction.model_validate(bad)


def test_oversized_plan_and_content_are_rejected(tmp_path):
    _, changes = services(tmp_path)
    action = ChangeAction(action="install_package", host="lab", target="nginx")
    with pytest.raises(ChangeDenied, match="outside policy"):
        changes.create("admin", "session-a", "Too many", [action] * 51)
    with pytest.raises(ValidationError):
        ChangeAction(action="write_managed_file", host="lab", target="app-config", value="x" * 32_001)


def test_scope_budget_session_and_expiry_are_rechecked(tmp_path):
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    authority, changes = services(tmp_path, lambda: current[0])
    action = ChangeAction(action="restart_service", host="lab", target="nginx")
    created = changes.create("admin", "session-a", "Restart", [action])
    changes.preview(created["id"], "admin", "session-a")
    approved = changes.approve(created["id"], "admin", "session-a")
    with pytest.raises(ChangeDenied, match="Unknown"):
        changes.get(created["id"], "admin", "attacker-session")
    current[0] += timedelta(minutes=6)
    with pytest.raises(ChangeDenied, match="expired"):
        changes.simulate(created["id"], approved["approval_token"], "admin", "session-a")
    authority.stop("admin", "session-a")
    with pytest.raises(AuthorityDenied):
        changes.create("admin", "session-a", "No authority", [action])


def test_invalid_state_transitions_are_denied(tmp_path):
    _, changes = services(tmp_path)
    action = ChangeAction(action="run_backup", host="lab", target="database-dump")
    created = changes.create("admin", "session-a", "Backup", [action])
    with pytest.raises(ChangeDenied, match="verified"):
        changes.accept(created["id"], "admin", "session-a")
    with pytest.raises(ChangeDenied, match="eligible"):
        changes.rollback(created["id"], "admin", "session-a")


def test_managed_file_backup_precedes_approval_and_incomplete_diff_cannot_pass(tmp_path):
    _, changes = services(tmp_path)
    action = ChangeAction(
        action="write_managed_file", host="lab", target="app-config",
        value="".join(f"key{i}=value\n" for i in range(600)),
    )
    created = changes.create("admin", "session-a", "Large config", [action])
    preview = changes.preview(created["id"], "admin", "session-a")
    item = preview["preview"][0]
    assert item["recovery_snapshot"]["verified"] is True
    assert item["managed_file"]["diff_truncated"] is True
    with pytest.raises(ChangeDenied, match="diff exceeds review bounds"):
        changes.approve(created["id"], "admin", "session-a")
