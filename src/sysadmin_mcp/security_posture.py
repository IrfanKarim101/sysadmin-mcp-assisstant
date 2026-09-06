"""Deterministic security posture checks using existing typed tools only."""

from __future__ import annotations

import asyncio
from pathlib import PurePosixPath
from typing import Any

from .config import HostConfig
from .executor import ReadOnlyExecutor
from .models import CommandResult

POSTURE_TIMEOUT_SECONDS = 60.0
AUTH_LOG = PurePosixPath("/var/log/auth.log")


class SecurityPostureService:
    def __init__(
        self, executor: ReadOnlyExecutor, *, timeout_seconds: float = POSTURE_TIMEOUT_SECONDS
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("posture timeout must be positive")
        self.executor = executor
        self.timeout_seconds = timeout_seconds

    async def inspect(self, host: HostConfig) -> dict[str, Any]:
        checks = [
            self.executor.check_services(host.name, "failed"),
            self.executor.check_ports(host.name),
            self.executor.who_is_on(host.name),
        ]
        auth_enabled = AUTH_LOG in host.allowed_logs
        if auth_enabled:
            checks.append(self.executor.grep_log(host.name, str(AUTH_LOG), "Failed password", 50))
        try:
            async with asyncio.timeout(self.timeout_seconds):
                completed = await asyncio.gather(*checks, return_exceptions=True)
        except TimeoutError:
            return {
                "host": host.name,
                "status": "timeout",
                "findings": [],
                "evidence": [],
                "limitations": ["The bounded posture check timed out."],
            }

        services, ports, users, *auth = completed
        evidence: list[dict[str, Any]] = []
        findings: list[dict[str, str]] = []
        _record("Failed services", services, evidence, findings, _failed_services)
        _record("Listening ports", ports, evidence, findings, _listening_ports)
        _record("Active sessions", users, evidence, findings, _active_sessions)
        if auth_enabled:
            _record("Failed SSH logins", auth[0], evidence, findings, _failed_logins)
        limitations = (
            []
            if auth_enabled
            else ["Failed-login analysis skipped: /var/log/auth.log is not allowlisted."]
        )
        status = (
            "warning"
            if any(item["severity"] in {"warning", "critical"} for item in findings)
            else "normal"
        )
        return {
            "host": host.name,
            "status": status,
            "findings": findings,
            "evidence": evidence,
            "limitations": limitations,
        }


def _record(
    name: str,
    value: Any,
    evidence: list[dict[str, Any]],
    findings: list[dict[str, str]],
    classifier,
) -> None:
    if isinstance(value, BaseException):
        findings.append(
            {
                "title": name,
                "severity": "unavailable",
                "summary": "This approved check failed or was denied.",
            }
        )
        return
    results = value if isinstance(value, tuple) else (value,)
    evidence.append({"check": name, "results": [_result(item) for item in results]})
    findings.append(classifier(results))


def _failed_services(results: tuple[CommandResult, ...]) -> dict[str, str]:
    count = sum(1 for line in results[0].stdout.splitlines() if line.strip())
    return {
        "title": "Failed services",
        "severity": "warning" if count else "normal",
        "summary": f"{count} failed service unit{'s' if count != 1 else ''} reported.",
    }


def _failed_logins(results: tuple[CommandResult, ...]) -> dict[str, str]:
    count = sum(1 for line in results[0].stdout.splitlines() if line.strip())
    severity = "critical" if count >= 10 else "warning" if count else "normal"
    return {
        "title": "Failed SSH logins",
        "severity": severity,
        "summary": f"{count} matching failed-password event{'s' if count != 1 else ''} in the bounded result.",
    }


def _listening_ports(results: tuple[CommandResult, ...]) -> dict[str, str]:
    count = sum(1 for line in results[0].stdout.splitlines() if line.strip())
    return {
        "title": "Listening ports",
        "severity": "info",
        "summary": f"{count} output lines observed; configure an expected-port baseline before classifying exposure.",
    }


def _active_sessions(results: tuple[CommandResult, ...]) -> dict[str, str]:
    count = sum(1 for line in results[-1].stdout.splitlines() if line.strip())
    return {
        "title": "Active sessions",
        "severity": "info",
        "summary": f"{count} active login session{'s' if count != 1 else ''} observed.",
    }


def _result(result: CommandResult) -> dict[str, Any]:
    return {
        "command": list(result.command),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_status": result.exit_status,
        "truncated": result.truncated,
    }
