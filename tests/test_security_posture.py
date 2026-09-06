from pathlib import PurePosixPath

import pytest

from sysadmin_mcp.config import HostConfig
from sysadmin_mcp.models import CommandResult
from sysadmin_mcp.security_posture import SecurityPostureService


def host(logs=("/var/log/auth.log",)):
    return HostConfig(
        name="vm",
        hostname="127.0.0.1",
        username="reader",
        known_hosts="C:/known_hosts",
        client_keys=(),
        password_env="SSH_PASSWORD",
        allowed_logs=frozenset(PurePosixPath(item) for item in logs),
    )


def result(command, output=""):
    return CommandResult((command,), output, "", 0)


class Executor:
    def __init__(self):
        self.calls = []

    async def check_services(self, name, state):
        self.calls.append(("services", name, state))
        return result("systemctl", "broken.service failed\n")

    async def check_ports(self, name):
        self.calls.append(("ports", name))
        return result("ss", "tcp LISTEN :22\n")

    async def who_is_on(self, name):
        self.calls.append(("users", name))
        return (result("w"), result("who", "olaf pts/0\n"))

    async def grep_log(self, name, path, pattern, lines):
        self.calls.append(("grep", name, path, pattern, lines))
        return result("grep", "one\ntwo\n")


@pytest.mark.asyncio
async def test_posture_uses_fixed_auth_pattern_and_classifies_findings():
    executor = Executor()
    report = await SecurityPostureService(executor).inspect(host())
    assert report["status"] == "warning"
    assert executor.calls[-1] == ("grep", "vm", "/var/log/auth.log", "Failed password", 50)
    assert {item["title"] for item in report["findings"]} == {
        "Failed services",
        "Listening ports",
        "Active sessions",
        "Failed SSH logins",
    }


@pytest.mark.asyncio
async def test_auth_analysis_is_skipped_when_log_is_not_allowlisted():
    executor = Executor()
    report = await SecurityPostureService(executor).inspect(host(("/var/log/syslog",)))
    assert not any(call[0] == "grep" for call in executor.calls)
    assert "not allowlisted" in report["limitations"][0]


@pytest.mark.asyncio
async def test_one_denied_check_is_isolated_and_details_are_hidden():
    executor = Executor()

    async def denied(name):
        raise RuntimeError("secret SSH path")

    executor.check_ports = denied
    report = await SecurityPostureService(executor).inspect(host())
    finding = next(item for item in report["findings"] if item["title"] == "Listening ports")
    assert finding["severity"] == "unavailable"
    assert "secret" not in finding["summary"]


def test_posture_timeout_must_be_positive():
    with pytest.raises(ValueError):
        SecurityPostureService(Executor(), timeout_seconds=0)
