from pathlib import PurePosixPath

import pytest

from sysadmin_mcp.audit import AuditEvent
from sysadmin_mcp.config import HostConfig
from sysadmin_mcp.executor import CommandResult, PolicyError, ReadOnlyExecutor
from sysadmin_mcp.policy import MAX_GREP_PATTERN_LENGTH, MAX_LINES, ReadOnlyCommandPolicy


class FakeTransport:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    async def run(self, host: HostConfig, argv) -> CommandResult:
        command = tuple(argv)
        self.commands.append(command)
        return CommandResult(command, "safe output", "", 0)


class MemoryAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self.events.append(event)


@pytest.fixture
def executor() -> tuple[ReadOnlyExecutor, FakeTransport]:
    transport = FakeTransport()
    host = HostConfig(
        name="test", hostname="test.example", username="sysadmin-readonly", known_hosts=None,
        client_keys=(), allowed_logs=frozenset({PurePosixPath("/var/log/syslog")}),
    )
    return ReadOnlyExecutor({"test": host}, transport, MemoryAudit()), transport


@pytest.mark.asyncio
async def test_grep_passes_pattern_as_an_argument(executor) -> None:
    service, transport = executor
    injection = "x'; rm -rf /; echo '"
    await service.grep_log("test", "/var/log/syslog", injection)
    assert transport.commands == [("grep", "-n", "-m", "100", "--", injection, "/var/log/syslog")]


@pytest.mark.asyncio
@pytest.mark.parametrize("logfile", ["../../etc/shadow", "/etc/shadow", "/var/log/../log/syslog"])
async def test_log_paths_must_be_exactly_allowlisted(executor, logfile: str) -> None:
    service, _ = executor
    with pytest.raises(PolicyError, match="allowlisted"):
        await service.read_log("test", logfile, "tail")


@pytest.mark.asyncio
async def test_line_and_state_bounds_are_enforced(executor) -> None:
    service, _ = executor
    with pytest.raises(PolicyError):
        await service.read_log("test", "/var/log/syslog", "tail", 501)
    with pytest.raises(PolicyError):
        await service.check_services("test", "activ; reboot")


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [0, -1, MAX_LINES + 1, True, 1.5, "10"])
async def test_oversized_or_non_integer_line_requests_are_rejected(
    executor, value
) -> None:
    service, transport = executor
    with pytest.raises(PolicyError, match="integer between"):
        await service.read_log("test", "/var/log/syslog", "tail", value)
    with pytest.raises(PolicyError, match="integer between"):
        await service.grep_log("test", "/var/log/syslog", "error", value)
    assert transport.commands == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pattern", ["", "x" * (MAX_GREP_PATTERN_LENGTH + 1), "ok\nreboot", "x\x00y"]
)
async def test_invalid_grep_patterns_are_rejected_before_transport(
    executor, pattern: str
) -> None:
    service, transport = executor
    with pytest.raises(PolicyError):
        await service.grep_log("test", "/var/log/syslog", pattern)
    assert transport.commands == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "logfile",
    ["/var/log/syslog\n/etc/shadow", "/var/log/syslog\x00", "/var/log/syslog;reboot"],
)
async def test_injection_shaped_log_paths_are_denied(executor, logfile: str) -> None:
    service, transport = executor
    with pytest.raises(PolicyError, match="allowlisted"):
        await service.read_log("test", logfile, "tail")
    assert transport.commands == []


@pytest.mark.asyncio
async def test_all_results_are_bounded_by_lines_and_bytes(executor) -> None:
    _, transport = executor
    transport_output = "abcdef\n" * 20

    async def run(host, argv):
        command = tuple(argv)
        transport.commands.append(command)
        return CommandResult(command, transport_output, transport_output, 0)

    transport.run = run
    hosts = {"test": executor[0]._policy.host("test")}
    service = ReadOnlyExecutor(
        hosts,
        transport,
        MemoryAudit(),
        max_output_lines=3,
        max_output_bytes=15,
    )
    result = await service.check_services("test")
    assert result.stdout == "abcdef\nabcdef\na"
    assert result.stderr == "abcdef\nabcdef\na"
    assert result.truncated is True
    assert len(result.stdout.encode()) <= 15


@pytest.mark.asyncio
async def test_transport_truncation_flag_is_preserved(executor) -> None:
    service, transport = executor

    async def run(host, argv):
        command = tuple(argv)
        transport.commands.append(command)
        return CommandResult(command, "bounded prefix", "", 255, truncated=True)

    transport.run = run
    result = await service.check_services("test")
    assert result.truncated is True


def test_policy_builders_need_no_ssh(executor) -> None:
    service, _ = executor
    policy: ReadOnlyCommandPolicy = service._policy
    assert policy.ports() == ("ss", "-tulnp")
    assert policy.services("failed")[-1] == "--state=failed"
    assert policy.resources() == (("top", "-bn1"), ("free", "-h"), ("vmstat", "1", "2"))
    assert policy.read_log("test", "/var/log/syslog", "cat", 7) == (
        "sed", "-n", "1,7p", "/var/log/syslog"
    )
    assert policy.active_users() == (("w", "-h"), ("who",))


@pytest.mark.asyncio
async def test_ss_falls_back_to_netstat(executor) -> None:
    service, transport = executor
    original = transport.run

    async def run(host, argv):
        result = await original(host, argv)
        if result.command[0] == "ss":
            return CommandResult(result.command, "", "not found", 127)
        return result

    transport.run = run
    await service.check_ports("test")
    assert transport.commands == [("ss", "-tulnp"), ("netstat", "-tulnp")]
