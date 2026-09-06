import asyncio
from pathlib import PurePosixPath

import pytest

from sysadmin_mcp.config import HostConfig
from sysadmin_mcp.fleet import MAX_FLEET_CONCURRENCY, FleetHealthService
from sysadmin_mcp.models import CommandResult


def hosts(count: int):
    return {f"vm-{i}": HostConfig(name=f"vm-{i}", hostname=f"10.0.0.{i}", username="reader", known_hosts=None, client_keys=(), allowed_logs=frozenset({PurePosixPath('/var/log/syslog')})) for i in range(count)}


class FleetExecutor:
    def __init__(self, failing: set[str] | None = None):
        self.active = 0
        self.peak = 0
        self.failing = failing or set()

    async def check_resources(self, host: str):
        self.active += 1
        self.peak = max(self.peak, self.active)
        await asyncio.sleep(0.01)
        self.active -= 1
        if host in self.failing:
            raise ConnectionError("secret transport detail")
        return (
            CommandResult(("top",), "%Cpu(s): 10.0 us, 80.0 id\n", "", 0),
            CommandResult(("free",), "Mem: 10Gi 2Gi 8Gi\n", "", 0),
            CommandResult(("vmstat",), "", "", 0),
        )

    async def check_disk_usage(self, host: str):
        return (
            CommandResult(("df",), "Filesystem Size Used Avail Use% Mounted on\n/dev/sda 20G 5G 15G 25% /\n", "", 0),
            CommandResult(("df",), "", "", 0),
        )


@pytest.mark.asyncio
async def test_fleet_snapshot_is_bounded_and_parses_metrics():
    executor = FleetExecutor()
    result = await FleetHealthService(executor).snapshot(hosts(12))
    assert len(result) == 12
    assert executor.peak <= MAX_FLEET_CONCURRENCY
    assert result[0]["status"] == "healthy"
    assert result[0]["cpu_percent"] == 20.0
    assert result[0]["memory_percent"] == 20.0
    assert result[0]["disk_percent"] == 25.0


@pytest.mark.asyncio
async def test_one_failed_host_does_not_fail_or_leak_details_from_fleet():
    result = await FleetHealthService(FleetExecutor({"vm-2"})).snapshot(hosts(4))
    assert [node["status"] for node in result] == ["healthy", "healthy", "offline", "healthy"]
    assert "secret" not in result[2]["message"]


def test_fleet_rejects_unsafe_concurrency_and_timeout_bounds():
    with pytest.raises(ValueError):
        FleetHealthService(FleetExecutor(), concurrency=MAX_FLEET_CONCURRENCY + 1)
    with pytest.raises(ValueError):
        FleetHealthService(FleetExecutor(), timeout_seconds=0)
