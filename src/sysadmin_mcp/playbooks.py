"""Deterministic investigation playbooks composed only of typed diagnostics."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from .executor import ReadOnlyExecutor
from .models import CommandResult

MAX_PLAYBOOK_STEPS = 3
PLAYBOOK_TIMEOUT_SECONDS = 45.0


@dataclass(frozen=True)
class Playbook:
    id: str
    name: str
    description: str
    steps: tuple[str, ...]


PLAYBOOKS = {
    item.id: item
    for item in (
        Playbook(
            "high-cpu",
            "High CPU",
            "Inspect CPU pressure and the busiest processes.",
            ("check_resources", "check_top_processes"),
        ),
        Playbook(
            "high-memory",
            "High memory",
            "Inspect memory pressure and memory-heavy processes.",
            ("check_resources", "check_top_processes"),
        ),
        Playbook(
            "disk-pressure",
            "Disk pressure",
            "Inspect filesystem space and inode exhaustion.",
            ("check_disk_usage",),
        ),
        Playbook(
            "service-outage",
            "Service outage",
            "Inspect failed services and listening ports.",
            ("check_services_failed", "check_ports"),
        ),
        Playbook(
            "network-issue",
            "Network issue",
            "Inspect interfaces, routes, and listening sockets.",
            ("check_network", "check_ports"),
        ),
        Playbook(
            "docker-health",
            "Docker health",
            "Inspect container state and host resource pressure.",
            ("check_docker", "check_resources"),
        ),
    )
}


class PlaybookRunner:
    def __init__(
        self, executor: ReadOnlyExecutor, *, timeout_seconds: float = PLAYBOOK_TIMEOUT_SECONDS
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("playbook timeout must be positive")
        self.executor = executor
        self.timeout_seconds = timeout_seconds

    def list(self) -> list[dict[str, Any]]:
        return [
            {"id": p.id, "name": p.name, "description": p.description, "steps": list(p.steps)}
            for p in PLAYBOOKS.values()
        ]

    async def run(self, playbook_id: str, host: str) -> dict[str, Any]:
        try:
            playbook = PLAYBOOKS[playbook_id]
        except KeyError as error:
            raise ValueError("unknown playbook") from error
        if len(playbook.steps) > MAX_PLAYBOOK_STEPS:
            raise RuntimeError("playbook exceeds the approved step limit")
        evidence: list[dict[str, Any]] = []
        try:
            async with asyncio.timeout(self.timeout_seconds):
                for step in playbook.steps:
                    results = await self._invoke(step, host)
                    evidence.append({"step": step, "results": [_result(item) for item in results]})
        except TimeoutError:
            return _response(playbook, host, "timeout", evidence, "Playbook timed out")
        except Exception:  # noqa: BLE001 - transport/policy details are not exposed
            return _response(
                playbook, host, "failed", evidence, "A diagnostic step failed or was denied"
            )
        return _response(playbook, host, "complete", evidence, "All approved steps completed")

    async def _invoke(self, step: str, host: str) -> tuple[CommandResult, ...]:
        if step == "check_resources":
            return tuple(await self.executor.check_resources(host))
        if step == "check_top_processes":
            return tuple(await self.executor.check_top_processes(host))
        if step == "check_disk_usage":
            return tuple(await self.executor.check_disk_usage(host))
        if step == "check_services_failed":
            return (await self.executor.check_services(host, "failed"),)
        if step == "check_ports":
            return (await self.executor.check_ports(host),)
        if step == "check_network":
            return tuple(await self.executor.check_network(host))
        if step == "check_docker":
            return tuple(await self.executor.check_docker(host))
        raise RuntimeError("playbook contains an unapproved step")


def _result(result: CommandResult) -> dict[str, Any]:
    return {
        "command": list(result.command),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_status": result.exit_status,
        "truncated": result.truncated,
    }


def _response(
    playbook: Playbook, host: str, status: str, evidence: list[dict[str, Any]], message: str
) -> dict[str, Any]:
    return {
        "id": playbook.id,
        "name": playbook.name,
        "host": host,
        "status": status,
        "message": message,
        "evidence": evidence,
    }
