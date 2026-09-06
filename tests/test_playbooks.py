import asyncio

import pytest

from sysadmin_mcp.models import CommandResult
from sysadmin_mcp.playbooks import MAX_PLAYBOOK_STEPS, PLAYBOOKS, PlaybookRunner
from sysadmin_mcp.web import PlaybookRequest


class FakeExecutor:
    def __init__(self):
        self.calls = []

    async def check_resources(self, host):
        self.calls.append(("resources", host))
        return (result("top"), result("free"), result("vmstat"))

    async def check_top_processes(self, host):
        self.calls.append(("processes", host))
        return (result("ps"), result("ps"))

    async def check_disk_usage(self, host):
        self.calls.append(("disk", host))
        return (result("df"), result("df"))

    async def check_services(self, host, state):
        self.calls.append(("services", host, state))
        return result("systemctl")

    async def check_ports(self, host):
        self.calls.append(("ports", host))
        return result("ss")

    async def check_network(self, host):
        self.calls.append(("network", host))
        return (result("ip"), result("ip"))

    async def check_docker(self, host):
        self.calls.append(("docker", host))
        return (result("docker"), result("docker"))


def result(command):
    return CommandResult((command,), "bounded evidence", "", 0)


@pytest.mark.asyncio
async def test_playbooks_have_bounded_fixed_steps_and_execute_in_order():
    executor = FakeExecutor()
    runner = PlaybookRunner(executor)
    assert all(len(item.steps) <= MAX_PLAYBOOK_STEPS for item in PLAYBOOKS.values())
    response = await runner.run("network-issue", "vm-1")
    assert response["status"] == "complete"
    assert executor.calls == [("network", "vm-1"), ("ports", "vm-1")]


def test_unknown_and_injection_shaped_playbook_ids_are_rejected():
    with pytest.raises(ValueError, match="unknown playbook"):
        asyncio.run(PlaybookRunner(FakeExecutor()).run("high-cpu; reboot", "vm-1"))
    with pytest.raises(ValueError):
        PlaybookRequest(playbook_id="high-cpu; reboot", host="vm-1")


@pytest.mark.asyncio
async def test_step_failure_is_sanitized_and_does_not_execute_later_steps():
    executor = FakeExecutor()

    async def fail(host):
        raise ConnectionError("private ssh detail")

    executor.check_network = fail
    response = await PlaybookRunner(executor).run("network-issue", "vm-1")
    assert response["status"] == "failed"
    assert "private" not in response["message"]
    assert executor.calls == []
