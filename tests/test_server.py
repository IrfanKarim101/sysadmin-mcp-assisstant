from __future__ import annotations

from pathlib import PurePosixPath

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from sysadmin_mcp.audit import AuditEvent
from sysadmin_mcp.config import HostConfig
from sysadmin_mcp.executor import CommandResult, ReadOnlyExecutor
from sysadmin_mcp.rate_limit import SlidingWindowRateLimiter
from sysadmin_mcp.server import create_mcp_server


class FakeTransport:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    async def run(self, host, argv) -> CommandResult:
        command = tuple(argv)
        self.commands.append(command)
        return CommandResult(command, f"raw: {command[0]}\n", "", 0)


class MemoryAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self.events.append(event)


@pytest.fixture
def mcp_adapter():
    host = HostConfig(
        name="test",
        hostname="localhost",
        username="reader",
        known_hosts=None,
        client_keys=(),
        allowed_logs=frozenset({PurePosixPath("/var/log/syslog")}),
    )
    transport = FakeTransport()
    audit = MemoryAudit()
    executor = ReadOnlyExecutor({"test": host}, transport, audit, session_id="mcp-test")
    return create_mcp_server(executor), transport, audit


@pytest.mark.asyncio
async def test_server_exposes_only_typed_read_only_tools(mcp_adapter) -> None:
    server, _, _ = mcp_adapter
    tools = await server.list_tools()
    assert {tool.name for tool in tools} == {
        "check_ports",
        "check_services",
        "check_resources",
        "read_log",
        "grep_log",
        "who_is_on",
        "check_disk_usage",
        "check_top_processes",
        "check_network",
        "check_docker",
    }
    for tool in tools:
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.annotations.idempotent_hint is True
        properties = tool.input_schema["properties"]
        assert "command" not in properties
        assert "argv" not in properties


@pytest.mark.asyncio
async def test_tool_schemas_publish_enums_and_bounds(mcp_adapter) -> None:
    server, _, _ = mcp_adapter
    tools = {tool.name: tool for tool in await server.list_tools()}

    service_state = tools["check_services"].input_schema["properties"]["state_filter"]
    state_schema = next(item for item in service_state["anyOf"] if "enum" in item)
    assert state_schema["enum"] == ["active", "inactive", "failed"]
    mode = tools["read_log"].input_schema["properties"]["mode"]
    assert mode["enum"] == ["head", "tail", "cat"]
    lines = tools["read_log"].input_schema["properties"]["lines"]
    assert lines["minimum"] == 1
    assert lines["maximum"] == 500
    pattern = tools["grep_log"].input_schema["properties"]["pattern"]
    assert pattern["minLength"] == 1
    assert pattern["maxLength"] == 256


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "arguments", "expected_commands"),
    [
        ("check_ports", {"host": "test"}, [("ss", "-tulnp")]),
        (
            "check_services",
            {"host": "test", "state_filter": "failed"},
            [
                (
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--no-pager",
                    "--no-legend",
                    "--state=failed",
                )
            ],
        ),
        (
            "read_log",
            {"host": "test", "logfile": "/var/log/syslog", "mode": "tail", "lines": 7},
            [("tail", "-n", "7", "/var/log/syslog")],
        ),
        (
            "grep_log",
            {
                "host": "test",
                "logfile": "/var/log/syslog",
                "pattern": "x'; touch /tmp/pwned",
                "max_lines": 9,
            },
            [("grep", "-n", "-m", "9", "--", "x'; touch /tmp/pwned", "/var/log/syslog")],
        ),
        (
            "check_resources",
            {"host": "test"},
            [("top", "-bn1"), ("free", "-h"), ("vmstat", "1", "2")],
        ),
        ("who_is_on", {"host": "test"}, [("w", "-h"), ("who",)]),
    ],
)
async def test_tools_route_only_to_fixed_executor_capabilities(
    mcp_adapter, tool_name, arguments, expected_commands
) -> None:
    server, transport, audit = mcp_adapter
    result = await server.call_tool(tool_name, arguments)
    assert result.is_error is False
    assert transport.commands == expected_commands
    assert result.structured_content is not None
    assert all(event.session_id == "mcp-test" for event in audit.events)


@pytest.mark.asyncio
async def test_raw_output_is_preserved_in_structured_result(mcp_adapter) -> None:
    server, _, _ = mcp_adapter
    result = await server.call_tool("check_ports", {"host": "test"})
    assert result.structured_content["raw"] == {
        "command": ["ss", "-tulnp"],
        "stdout": "raw: ss\n",
        "stderr": "",
        "exit_status": 0,
        "truncated": False,
    }
    assert list(result.structured_content) == ["raw", "summary", "display_markdown"]
    display = result.structured_content["display_markdown"]
    assert display.index("## Raw output") < display.index("## Summary")
    assert "raw: ss\n" in display


@pytest.mark.asyncio
async def test_disallowed_log_path_cannot_reach_transport(mcp_adapter) -> None:
    server, transport, audit = mcp_adapter
    with pytest.raises(ToolError, match="allowlisted"):
        await server.call_tool(
            "read_log",
            {"host": "test", "logfile": "/etc/shadow", "mode": "tail", "lines": 10},
        )
    assert transport.commands == []
    assert audit.events[-1].status == "denied"


@pytest.mark.asyncio
async def test_mcp_rate_limit_denial_is_clear_and_does_not_reach_transport(
    mcp_adapter,
) -> None:
    _, transport, audit = mcp_adapter
    host = HostConfig(
        "test",
        "localhost",
        "reader",
        None,
        (),
        frozenset({PurePosixPath("/var/log/syslog")}),
    )
    executor = ReadOnlyExecutor({"test": host}, transport, audit)
    server = create_mcp_server(
        executor, rate_limiter=SlidingWindowRateLimiter(1, 60)
    )
    await server.call_tool("check_ports", {"host": "test"})
    with pytest.raises(ToolError, match="Rate limit exceeded"):
        await server.call_tool("check_ports", {"host": "test"})
    assert transport.commands == [("ss", "-tulnp")]
