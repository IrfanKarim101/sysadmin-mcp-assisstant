from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

import pytest

from sysadmin_mcp.authority import AuthorityDenied, AuthorityService
from sysadmin_mcp.config import HostConfig


class AuditCapture:
    def __init__(self): self.events = []
    def append(self, event): self.events.append(event)


def host(name: str, environment: str) -> HostConfig:
    return HostConfig(
        name=name, hostname="192.0.2.10", username="reader",
        known_hosts="C:/known_hosts", client_keys=(Path("C:/id"),),
        allowed_logs=frozenset({PurePosixPath("/var/log/syslog")}),
        environment=environment,
    )


def arm(service: AuthorityService, **changes):
    values = {
        "mode": "autonomous_lab", "username": "admin", "session_id": "session-a",
        "hosts": ["lab"], "capabilities": ["services"], "duration_minutes": 15,
        "action_budget": 5, "concurrency": 1,
    }
    values.update(changes)
    return service.arm(**values)


def test_autonomous_lab_is_scoped_expiring_and_fail_closed_for_production():
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    audit = AuditCapture()
    service = AuthorityService(
        {"lab": host("lab", "disposable_lab"), "prod": host("prod", "production")},
        audit, now=lambda: current[0],
    )
    with pytest.raises(AuthorityDenied, match="only permits"):
        arm(service, hosts=["prod"])
    state = arm(service)
    assert state["mode"] == "autonomous_lab" and state["status"] == "active"
    current[0] += timedelta(minutes=16)
    assert service.current()["mode"] == "observe"
    assert [event.tool_name for event in audit.events] == [
        "automation_mode_denied", "automation_mode_armed", "automation_mode_expired"
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"hosts": ["lab;reboot"]},
        {"hosts": ["lab", "lab"]},
        {"capabilities": ["shell"]},
        {"duration_minutes": 61},
        {"action_budget": 51},
        {"concurrency": 2},
    ],
)
def test_malicious_or_oversized_authority_scope_is_rejected(changes):
    service = AuthorityService({"lab": host("lab", "development")}, AuditCapture())
    with pytest.raises(AuthorityDenied):
        arm(service, **changes)


def test_pause_resume_and_stop_are_bound_to_owning_session():
    service = AuthorityService({"lab": host("lab", "development")}, AuditCapture())
    arm(service)
    with pytest.raises(AuthorityDenied, match="another authenticated session"):
        service.pause("admin", "attacker-session")
    assert service.pause("admin", "session-a")["status"] == "paused"
    assert service.resume("admin", "session-a")["status"] == "active"
    assert service.stop("admin", "session-a")["mode"] == "observe"
