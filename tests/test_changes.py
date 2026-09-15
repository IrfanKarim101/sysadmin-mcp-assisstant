from datetime import UTC, datetime, timedelta
from dataclasses import replace
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
    assert approved["approval_owner"] == "admin"
    assert approved["approval_expires_at"] is not None
    assert approved["rollback_available"] is True
    result = changes.simulate(created["id"], approved["approval_token"], "admin", "session-a")
    assert result["state"] == "verifying"
    assert result["approval_expires_at"] is None
    assert result["approval_owner"] is None
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


def test_revision_replaces_plan_and_invalidates_existing_approval(tmp_path):
    _, changes = services(tmp_path)
    original_action = ChangeAction(action="restart_service", host="lab", target="nginx")
    original = changes.create("admin", "session-a", "RestartRestart", [original_action])
    changes.preview(original["id"], "admin", "session-a")
    approved = changes.approve(original["id"], "admin", "session-a")

    replacement_action = ChangeAction(action="run_backup", host="lab", target="database-dump")
    replacement = changes.revise(
        original["id"], "admin", "session-a", "Backup first", [replacement_action]
    )

    assert replacement["id"] != original["id"]
    assert replacement["state"] == "planned"
    assert replacement["actions"] == [replacement_action.model_dump()]
    assert changes.get(original["id"], "admin", "session-a")["state"] == "cancelled"
    with pytest.raises(ChangeDenied, match="already used"):
        changes.simulate(
            original["id"], approved["approval_token"], "admin", "session-a"
        )


def test_executed_transaction_cannot_be_revised(tmp_path):
    _, changes = services(tmp_path)
    action = ChangeAction(action="restart_service", host="lab", target="nginx")
    created = changes.create("admin", "session-a", "Restart", [action])
    changes.preview(created["id"], "admin", "session-a")
    approved = changes.approve(created["id"], "admin", "session-a")
    changes.simulate(created["id"], approved["approval_token"], "admin", "session-a")
    with pytest.raises(ChangeDenied, match="unexecuted"):
        changes.revise(created["id"], "admin", "session-a", "Changed", [action])


def test_skip_host_creates_reduced_plan_and_invalidates_approval(tmp_path):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    second = replace(host(), name="lab-b", hostname="192.0.2.11")
    hosts = {"lab": host(), "lab-b": second}
    authority = AuthorityService(hosts, audit)
    authority.arm(
        mode="guided", username="admin", session_id="session-a",
        hosts=["lab", "lab-b"], capabilities=["services"],
        duration_minutes=15, action_budget=5, concurrency=2,
    )
    changes = ChangeTransactionService(
        audit.path, authority, audit, services=ServicePlanner(hosts)
    )
    actions = [
        ChangeAction(action="restart_service", host="lab", target="nginx"),
        ChangeAction(action="restart_service", host="lab-b", target="nginx"),
    ]
    created = changes.create("admin", "session-a", "Fleet restart", actions)
    changes.preview(created["id"], "admin", "session-a")
    approved = changes.approve(created["id"], "admin", "session-a")

    replacement = changes.skip_host(
        created["id"], "admin", "session-a", "lab-b"
    )

    assert {item["host"] for item in replacement["actions"]} == {"lab"}
    assert replacement["state"] == "planned"
    assert changes.get(created["id"], "admin", "session-a")["state"] == "cancelled"
    with pytest.raises(ChangeDenied, match="already used"):
        changes.simulate(
            created["id"], approved["approval_token"], "admin", "session-a"
        )


def test_skip_host_rejects_unknown_only_or_started_host(tmp_path):
    _, changes = services(tmp_path)
    action = ChangeAction(action="restart_service", host="lab", target="nginx")
    created = changes.create("admin", "session-a", "Restart", [action])
    with pytest.raises(ChangeDenied, match="not part"):
        changes.skip_host(created["id"], "admin", "session-a", "other")
    with pytest.raises(ChangeDenied, match="only host"):
        changes.skip_host(created["id"], "admin", "session-a", "lab")
    changes.preview(created["id"], "admin", "session-a")
    approved = changes.approve(created["id"], "admin", "session-a")
    changes.simulate(created["id"], approved["approval_token"], "admin", "session-a")
    with pytest.raises(ChangeDenied, match="before execution"):
        changes.skip_host(created["id"], "admin", "session-a", "lab")


def test_multi_host_simulation_records_canary_waves_limits_and_releases_locks(tmp_path):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    second = replace(host(), name="lab-b", hostname="192.0.2.11")
    hosts = {"lab": host(), "lab-b": second}
    authority = AuthorityService(hosts, audit)
    authority.arm(
        mode="guided", username="admin", session_id="session-a",
        hosts=["lab", "lab-b"], capabilities=["services"],
        duration_minutes=15, action_budget=5, concurrency=2,
    )
    changes = ChangeTransactionService(
        audit.path, authority, audit, services=ServicePlanner(hosts)
    )
    actions = [
        ChangeAction(action="restart_service", host="lab-b", target="nginx"),
        ChangeAction(action="restart_service", host="lab", target="nginx"),
    ]
    created = changes.create("admin", "session-a", "Fleet restart", actions)
    changes.preview(created["id"], "admin", "session-a")
    approved = changes.approve(created["id"], "admin", "session-a")
    result = changes.simulate(
        created["id"], approved["approval_token"], "admin", "session-a"
    )

    rollout = result["evidence"][-1]["fleet_rollout"]
    assert rollout["canary"] == "lab"
    assert rollout["waves"] == [["lab"], ["lab-b"]]
    assert rollout["concurrency"] == 2
    assert rollout["timeout_seconds"] == 60
    assert rollout["circuit_breaker"] == "closed"
    with changes._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM change_host_locks").fetchone()[0] == 0


def test_live_host_lock_blocks_overlapping_transaction(tmp_path):
    _, changes = services(tmp_path)
    now = changes._utc_now()
    with changes._connect() as db:
        db.execute(
            "INSERT INTO change_host_locks(host,transaction_id,acquired_at,expires_at) VALUES (?,?,?,?)",
            ("lab", "other", now.isoformat(), (now + timedelta(seconds=60)).isoformat()),
        )
    with pytest.raises(ChangeDenied, match="locked"):
        changes._acquire_host_locks("current", ["lab"])


def test_canary_failure_opens_circuit_and_skips_later_waves(tmp_path):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    second = replace(host(), name="lab-b", hostname="192.0.2.11")
    hosts = {"lab": host(), "lab-b": second}
    authority = AuthorityService(hosts, audit)
    authority.arm(
        mode="guided", username="admin", session_id="session-a",
        hosts=["lab", "lab-b"], capabilities=["services"],
        duration_minutes=15, action_budget=5, concurrency=1,
    )
    changes = ChangeTransactionService(
        audit.path, authority, audit, services=ServicePlanner(hosts)
    )
    actions = [
        ChangeAction(action="restart_service", host="lab", target="nginx"),
        ChangeAction(action="restart_service", host="lab-b", target="nginx"),
    ]
    created = changes.create("admin", "session-a", "Fleet restart", actions)
    changes.preview(created["id"], "admin", "session-a")
    approved = changes.approve(created["id"], "admin", "session-a")
    result = changes.simulate(
        created["id"], approved["approval_token"], "admin", "session-a",
        simulated_host_outcomes={"lab": False},
    )

    assert result["state"] == "failed"
    rollout = result["evidence"][-1]["fleet_rollout"]
    assert rollout["circuit_breaker"] == "open"
    assert rollout["failed_host"] == "lab"
    assert rollout["skipped_hosts"] == ["lab-b"]
    assert [item["state"] for item in rollout["hosts"]] == [
        "simulated_failed", "skipped_circuit_open"
    ]
    assert [item["stage"] for item in result["evidence"]] == ["backup", "apply"]
    assert result["rollback_available"] is True


def test_stepwise_simulation_advances_exactly_one_stage_at_a_time(tmp_path):
    authority, changes = services(tmp_path)
    action = ChangeAction(action="restart_service", host="lab", target="nginx")
    created = changes.create("admin", "session-a", "Stepwise restart", [action])
    changes.preview(created["id"], "admin", "session-a")
    approved = changes.approve(created["id"], "admin", "session-a")

    current = changes.simulate(
        created["id"], approved["approval_token"], "admin", "session-a",
        stop_after_backup=True,
    )
    assert current["state"] == "backed_up"
    assert [item["stage"] for item in current["evidence"]] == ["backup"]

    authority.pause("admin", "session-a")
    with pytest.raises(AuthorityDenied, match="not active"):
        changes.advance(created["id"], "admin", "session-a")
    authority.resume("admin", "session-a")

    expected = [
        ("applying", "apply"), ("validating", "validate"),
        ("activating", "activate"), ("verifying", "verify"),
    ]
    for state, stage in expected:
        current = changes.advance(created["id"], "admin", "session-a")
        assert current["state"] == state
        assert current["evidence"][-1]["stage"] == stage
    with pytest.raises(ChangeDenied, match="no stage"):
        changes.advance(created["id"], "admin", "session-a")


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
