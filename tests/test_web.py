import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from sysadmin_mcp.audit import SQLiteAuditLog
from sysadmin_mcp.authority import AuthorityService
from sysadmin_mcp.auth import MAX_LOGIN_FAILURES, AuthStore
from sysadmin_mcp.backups import BackupService
from sysadmin_mcp.config import ConfigError, HostConfig, validate_host
from sysadmin_mcp.models import CommandResult
from sysadmin_mcp.web import AgentService, ChatRequest, _host_discovery_error, create_app


def host() -> HostConfig:
    return HostConfig(
        name="olaf-ubuntu",
        hostname="192.168.0.109",
        username="olaf",
        known_hosts="C:/Users/test/.ssh/known_hosts",
        client_keys=(),
        allowed_logs=frozenset({PurePosixPath("/var/log/auth.log")}),
        password_env="SYSADMIN_SSH_PASSWORD_OLAF",
    )


class FakeExecutor:
    def __init__(self): self.hosts = []
    async def check_ports(self, selected):
        self.hosts.append(selected)
        return CommandResult(("ss", "-tulnp"), "tcp LISTEN :22\n", "", 0)


class FakeResponses:
    def __init__(self):
        self.calls = 0
        self.requests = []
    async def create(self, **kwargs):
        self.calls += 1
        self.requests.append(kwargs)
        if self.calls == 1:
            call = SimpleNamespace(type="function_call", name="check_ports", arguments=json.dumps({"host": "attacker; rm -rf /"}), call_id="call-1")
            return SimpleNamespace(output=[call], output_text="", id="response-1")
        return SimpleNamespace(output=[], output_text="Port 22 is listening.", id="response-2")


@pytest.mark.asyncio
async def test_agent_forces_selected_allowlisted_host_over_model_input():
    executor = FakeExecutor()
    client = SimpleNamespace(responses=FakeResponses())
    service = AgentService({"olaf-ubuntu": host()}, executor, model="test", client=client)
    events = [json.loads(line) async for line in service.stream(ChatRequest(message="ports", host="olaf-ubuntu"))]
    assert executor.hosts == ["olaf-ubuntu"]
    assert [event["type"] for event in events] == ["thinking", "tool_start", "tool_result", "summary", "done"]
    assert "tools" not in client.responses.requests[1]
    assert client.responses.requests[1]["input"][-1]["role"] == "user"


@pytest.mark.asyncio
async def test_unknown_host_never_reaches_llm_or_executor():
    service = AgentService({"olaf-ubuntu": host()}, FakeExecutor(), model="test", client=SimpleNamespace(responses=FakeResponses()))
    events = [json.loads(line) async for line in service.stream(ChatRequest(message="ports", host="bad;host"))]
    assert events == [{"type": "error", "message": "Unknown or unapproved host."}]


def test_password_environment_name_is_validated():
    invalid = HostConfig(**{**host().__dict__, "password_env": "PASSWORD;whoami"})
    with pytest.raises(ConfigError, match="password_env"):
        validate_host(invalid)


def test_host_discovery_errors_distinguish_access_policy_and_unreachable_network():
    assert "outbound firewall" in _host_discovery_error(PermissionError("access denied"))
    assert "unreachable" in _host_discovery_error(OSError("private local detail"))
    assert "private local detail" not in _host_discovery_error(OSError("private local detail"))


def test_api_does_not_expose_credentials(tmp_path: Path):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    service = AgentService({"olaf-ubuntu": host()}, FakeExecutor(), model="test", client=SimpleNamespace(responses=FakeResponses()))
    routes = {route.path for route in create_app(service, audit).routes}
    assert routes == {
        "/openapi.json", "/api/hosts", "/api/providers", "/api/audit", "/api/chat"
        , "/api/chat/sessions/{session_id}", "/api/hosts/discover-key",
        "/api/hosts/decide-key", "/api/chat/sessions", "/api/auth/login",
        "/api/hosts/remove",
        "/api/auth/me", "/api/auth/change-password", "/api/auth/logout",
        "/api/auth/sessions", "/api/auth/sessions/revoke", "/api/auth/events",
        "/api/fleet/health", "/api/playbooks", "/api/playbooks/run",
        "/api/fleet/hosts/{host_name}",
        "/api/security/posture"
        , "/api/remediation/actions", "/api/remediation/restart/preview",
        "/api/remediation/restart/execute", "/api/backups/jobs",
        "/api/backups/preview", "/api/backups/execute", "/api/authority",
        "/api/authority/arm", "/api/authority/pause", "/api/authority/resume",
        "/api/authority/stop", "/api/authority/emergency-stop", "/api/hosts/classify"
        , "/api/changes", "/api/changes/{transaction_id}",
        "/api/managed-files/policies",
        "/api/packages/policies",
        "/api/services/policies",
        "/api/changes/{transaction_id}/preview", "/api/changes/{transaction_id}/approve",
        "/api/changes/{transaction_id}/simulate", "/api/changes/{transaction_id}/accept",
        "/api/changes/{transaction_id}/rollback", "/api/changes/{transaction_id}/cancel"
    }


def test_unauthenticated_response_keeps_cors_headers(tmp_path: Path):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    service = AgentService(
        {"olaf-ubuntu": host()},
        FakeExecutor(),
        model="test",
        client=SimpleNamespace(responses=FakeResponses()),
    )
    response = TestClient(create_app(service, audit)).get(
        "/api/hosts", headers={"origin": "http://localhost:3000"}
    )
    assert response.status_code == 401
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_private_lan_origin_is_allowed_but_public_origin_is_not(tmp_path: Path):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    service = AgentService(
        {"olaf-ubuntu": host()}, FakeExecutor(), model="test",
        client=SimpleNamespace(responses=FakeResponses()),
    )
    client = TestClient(create_app(service, audit))
    lan = client.get("/api/hosts", headers={"origin": "http://192.168.0.25:3000"})
    assert lan.status_code == 401
    assert lan.headers["access-control-allow-origin"] == "http://192.168.0.25:3000"
    public = client.get("/api/hosts", headers={"origin": "http://203.0.113.10:3000"})
    assert public.status_code == 401
    assert "access-control-allow-origin" not in public.headers


def test_login_throttle_and_session_revocation_require_csrf(tmp_path: Path):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    service = AgentService(
        {"olaf-ubuntu": host()}, FakeExecutor(), model="test",
        client=SimpleNamespace(responses=FakeResponses()),
    )
    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    app = create_app(service, audit, auth=AuthStore(audit.path, now=lambda: current[0]))
    attacker = TestClient(app)
    for _ in range(MAX_LOGIN_FAILURES):
        assert attacker.post(
            "/api/auth/login", json={"username": "admin", "password": "wrong"}
        ).status_code == 401
    throttled = attacker.post(
        "/api/auth/login", json={"username": "admin", "password": "admin"}
    )
    assert throttled.status_code == 429
    assert 1 <= int(throttled.headers["retry-after"]) <= 901

    current[0] += timedelta(minutes=16)
    first, second = TestClient(app), TestClient(app)
    first_login = first.post(
        "/api/auth/login", json={"username": "admin", "password": "admin"},
        headers={"x-forwarded-for": "192.0.2.1"},
    ).json()
    assert first.post(
        "/api/auth/change-password",
        json={"current_password": "admin", "new_password": "a-secure-password"},
        headers={"x-csrf-token": first_login["csrf_token"]},
    ).status_code == 200
    second.post(
        "/api/auth/login", json={"username": "admin", "password": "a-secure-password"},
        headers={"x-forwarded-for": "192.0.2.2"},
    )
    sessions = first.get("/api/auth/sessions").json()
    target = next(row for row in sessions if not row["current"])
    assert first.post(
        "/api/auth/sessions/revoke", json={"session_id": target["session_id"]}
    ).status_code == 403
    assert first.post(
        "/api/auth/sessions/revoke", json={"session_id": target["session_id"]},
        headers={"x-csrf-token": first_login["csrf_token"]},
    ).json() == {"revoked": True}
    assert second.get("/api/auth/me").status_code == 401


def test_request_rejects_disabled_or_unknown_provider():
    assert ChatRequest(message="ports", host="olaf-ubuntu", provider="local").provider == "local"
    with pytest.raises(ValueError):
        ChatRequest(message="ports", host="olaf-ubuntu", provider="anthropic")
    with pytest.raises(ValueError):
        ChatRequest(message="ports", host="olaf-ubuntu", provider="openai;gemini")


def test_authority_api_requires_reauthentication_csrf_and_resets_on_logout(tmp_path: Path):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    managed_host = HostConfig(**{**host().__dict__, "environment": "development"})
    service = AgentService(
        {managed_host.name: managed_host}, FakeExecutor(), model="test",
        client=SimpleNamespace(responses=FakeResponses()),
    )
    authority = AuthorityService(service.hosts, audit)
    client = TestClient(create_app(service, audit, authority=authority))
    body = {
        "mode": "autonomous_lab", "hosts": [managed_host.name],
        "capabilities": ["services"], "duration_minutes": 15,
        "action_budget": 2, "concurrency": 1, "password": "a-secure-password",
    }
    assert client.post("/api/authority/arm", json=body).status_code == 401
    login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin"}
    ).json()
    csrf = {"x-csrf-token": login["csrf_token"]}
    assert client.post(
        "/api/auth/change-password",
        json={"current_password": "admin", "new_password": "a-secure-password"},
        headers=csrf,
    ).status_code == 200
    assert client.post("/api/authority/arm", json=body).status_code == 403
    assert client.post("/api/authority/arm", json=body, headers=csrf).status_code == 200
    visible = client.get("/api/authority").json()
    assert visible["mode"] == "autonomous_lab" and "session_id" not in visible
    assert client.post("/api/authority/pause", headers=csrf).json()["status"] == "paused"
    assert client.post("/api/auth/logout", headers=csrf).status_code == 204
    assert authority.current()["mode"] == "observe"


def test_backup_api_requires_authentication_reauthentication_and_fixed_job(tmp_path: Path):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    transport = type(
        "BackupTransport",
        (),
        {"run": lambda self, target, command: asyncio.sleep(
            0, result=CommandResult(command, "dump completed\n", "", 0)
        )},
    )()
    backup_host = HostConfig(**{
        **host().__dict__, "backup_jobs": frozenset({"database-dump"})
    })
    service = AgentService(
        {"olaf-ubuntu": backup_host}, FakeExecutor(), model="test",
        client=SimpleNamespace(responses=FakeResponses()),
    )
    client = TestClient(create_app(
        service, audit, backups=BackupService({"olaf-ubuntu": backup_host}, transport, audit)
    ))
    assert client.get("/api/backups/jobs").status_code == 401
    login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin"}
    ).json()
    csrf = {"x-csrf-token": login["csrf_token"]}
    assert client.post(
        "/api/auth/change-password",
        json={"current_password": "admin", "new_password": "a-secure-password"},
        headers=csrf,
    ).status_code == 200
    assert client.get("/api/backups/jobs").json() == [
        {"host": "olaf-ubuntu", "backup_jobs": ["database-dump"]}
    ]
    armed = client.post(
        "/api/authority/arm",
        json={"mode": "guided", "hosts": ["olaf-ubuntu"],
              "capabilities": ["backups"], "duration_minutes": 15,
              "action_budget": 2, "concurrency": 1,
              "password": "a-secure-password"},
        headers=csrf,
    )
    assert armed.status_code == 200
    assert client.post(
        "/api/backups/preview",
        json={"host": "olaf-ubuntu", "job": "database-dump", "password": "wrong"},
        headers=csrf,
    ).status_code == 401
    assert client.post(
        "/api/backups/preview",
        json={"host": "olaf-ubuntu", "job": "database-dump;id",
              "password": "a-secure-password"},
        headers=csrf,
    ).status_code == 422
    preview = client.post(
        "/api/backups/preview",
        json={"host": "olaf-ubuntu", "job": "database-dump",
              "password": "a-secure-password"},
        headers=csrf,
    ).json()
    result = client.post(
        "/api/backups/execute",
        json={"approval_token": preview["approval_token"]},
        headers=csrf,
    )
    assert result.status_code == 200
    assert result.json()["verified"] is True
    assert client.post(
        "/api/backups/execute",
        json={"approval_token": preview["approval_token"]},
        headers=csrf,
    ).status_code == 400


class SlowResponses:
    async def create(self, **kwargs):
        await asyncio.sleep(1)


@pytest.mark.asyncio
async def test_model_timeout_ends_stream_and_reenables_client():
    service = AgentService(
        {"olaf-ubuntu": host()},
        FakeExecutor(),
        model="test",
        client=SimpleNamespace(responses=SlowResponses()),
        model_timeout_seconds=0.001,
    )
    events = [
        json.loads(line)
        async for line in service.stream(ChatRequest(message="ports", host="olaf-ubuntu"))
    ]
    assert [event["type"] for event in events] == ["thinking", "error", "done"]
