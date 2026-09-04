import asyncio
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from sysadmin_mcp.audit import SQLiteAuditLog
from sysadmin_mcp.config import ConfigError, HostConfig, validate_host
from sysadmin_mcp.models import CommandResult
from sysadmin_mcp.web import AgentService, ChatRequest, create_app


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


def test_api_does_not_expose_credentials(tmp_path: Path):
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    service = AgentService({"olaf-ubuntu": host()}, FakeExecutor(), model="test", client=SimpleNamespace(responses=FakeResponses()))
    routes = {route.path for route in create_app(service, audit).routes}
    assert routes == {
        "/openapi.json", "/api/hosts", "/api/providers", "/api/audit", "/api/chat"
        , "/api/chat/sessions/{session_id}"
    }


def test_request_rejects_disabled_or_unknown_provider():
    with pytest.raises(ValueError):
        ChatRequest(message="ports", host="olaf-ubuntu", provider="anthropic")
    with pytest.raises(ValueError):
        ChatRequest(message="ports", host="olaf-ubuntu", provider="openai;gemini")


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
