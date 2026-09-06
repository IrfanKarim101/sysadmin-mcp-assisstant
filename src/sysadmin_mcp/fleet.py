"""Bounded, failure-isolated fleet health snapshots."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from typing import Any

from .config import HostConfig
from .executor import ReadOnlyExecutor

MAX_FLEET_HOSTS = 50
MAX_FLEET_CONCURRENCY = 4
FLEET_HOST_TIMEOUT_SECONDS = 75.0


class FleetHealthService:
    def __init__(
        self,
        executor: ReadOnlyExecutor,
        *,
        concurrency: int = MAX_FLEET_CONCURRENCY,
        timeout_seconds: float = FLEET_HOST_TIMEOUT_SECONDS,
    ) -> None:
        if not 1 <= concurrency <= MAX_FLEET_CONCURRENCY or timeout_seconds <= 0:
            raise ValueError("fleet bounds are invalid")
        self.executor = executor
        self.concurrency = concurrency
        self.timeout_seconds = timeout_seconds

    async def snapshot(self, hosts: Mapping[str, HostConfig]) -> list[dict[str, Any]]:
        selected = list(hosts.values())[:MAX_FLEET_HOSTS]
        semaphore = asyncio.Semaphore(self.concurrency)

        async def inspect(host: HostConfig) -> dict[str, Any]:
            async with semaphore:
                try:
                    async with asyncio.timeout(self.timeout_seconds):
                        resources, disks = await asyncio.gather(
                            self.executor.check_resources(host.name),
                            self.executor.check_disk_usage(host.name),
                        )
                    return _healthy_snapshot(host, resources[0].stdout, resources[1].stdout, disks[0].stdout)
                except TimeoutError:
                    return _offline_snapshot(host, "Health check timed out")
                except Exception:  # noqa: BLE001 - fleet failures are intentionally isolated
                    return _offline_snapshot(host, "Host is unreachable or diagnostics were denied")

        return list(await asyncio.gather(*(inspect(host) for host in selected)))


def _healthy_snapshot(host: HostConfig, top: str, free: str, disk: str) -> dict[str, Any]:
    cpu = _cpu_percent(top)
    memory = _memory_percent(free)
    disk_used = _root_disk_percent(disk)
    warning = (
        (cpu is not None and cpu >= host.thresholds.cpu_percent)
        or (memory is not None and memory >= host.thresholds.memory_percent)
        or (disk_used is not None and disk_used >= 90)
    )
    return {
        "name": host.name,
        "hostname": host.hostname,
        "status": "warning" if warning else "healthy",
        "cpu_percent": cpu,
        "memory_percent": memory,
        "disk_percent": disk_used,
        "message": "One or more thresholds were exceeded" if warning else "Diagnostics completed",
    }


def _offline_snapshot(host: HostConfig, message: str) -> dict[str, Any]:
    return {"name": host.name, "hostname": host.hostname, "status": "offline",
            "cpu_percent": None, "memory_percent": None, "disk_percent": None,
            "message": message}


def _cpu_percent(output: str) -> float | None:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*id(?:,|\s|$)", output)
    return round(100 - float(match.group(1)), 1) if match else None


def _memory_percent(output: str) -> float | None:
    for line in output.splitlines():
        if line.startswith("Mem:"):
            parts = line.split()
            if len(parts) >= 3:
                total, used = _size(parts[1]), _size(parts[2])
                if total:
                    return round(used / total * 100, 1)
    return None


def _root_disk_percent(output: str) -> float | None:
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[-1] == "/" and parts[-2].endswith("%"):
            try:
                return float(parts[-2][:-1])
            except ValueError:
                return None
    return None


def _size(value: str) -> float | None:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMGTPE]?i?)?", value)
    if not match:
        return None
    scales = {"": 1, "K": 10**3, "Ki": 2**10, "M": 10**6, "Mi": 2**20,
              "G": 10**9, "Gi": 2**30, "T": 10**12, "Ti": 2**40}
    scale = scales.get(match.group(2) or "")
    return float(match.group(1)) * scale if scale else None
