"""Fail-closed, in-memory authority modes for supervised lab automation."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from uuid import uuid4

from .audit import AuditEvent, AuditSink
from .config import HostConfig

MODES = frozenset({"observe", "guided", "autonomous_lab"})
CAPABILITIES = frozenset({"backups", "managed_files", "packages", "services"})
AUTONOMOUS_ENVIRONMENTS = frozenset({"development", "disposable_lab"})


class AuthorityDenied(ValueError):
    """An authority transition was rejected by deterministic policy."""


@dataclass(frozen=True)
class AuthorityState:
    mode: str = "observe"
    status: str = "inactive"
    owner: str | None = None
    session_id: str | None = None
    hosts: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    action_budget: int = 0
    concurrency: int = 0
    armed_at: str | None = None
    expires_at: str | None = None


class AuthorityService:
    """Owns temporary mode state; restarting the backend returns to Observe."""

    def __init__(
        self,
        hosts: Mapping[str, HostConfig],
        audit: AuditSink,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._hosts = dict(hosts)
        self._audit = audit
        self._now = now or (lambda: datetime.now(UTC))
        self._state = AuthorityState()
        self._lock = Lock()

    def replace_hosts(self, hosts: Mapping[str, HostConfig]) -> None:
        with self._lock:
            previous_hosts = self._hosts
            self._hosts = dict(hosts)
            if self._state.mode != "observe" and any(
                name not in self._hosts or previous_hosts.get(name) != self._hosts.get(name)
                for name in self._state.hosts
            ):
                self._reset("host_scope_changed")

    def current(self) -> dict[str, object]:
        with self._lock:
            self._expire_if_needed()
            return asdict(self._state)

    def arm(
        self,
        *,
        mode: str,
        username: str,
        session_id: str,
        hosts: Sequence[str],
        capabilities: Sequence[str],
        duration_minutes: int,
        action_budget: int,
        concurrency: int,
    ) -> dict[str, object]:
        with self._lock:
            try:
                self._validate_arm(
                    mode, hosts, capabilities, duration_minutes, action_budget, concurrency
                )
            except AuthorityDenied as error:
                self._record("automation_mode_denied", username, session_id, {
                    "mode": mode, "hosts": list(hosts), "reason": str(error)
                }, "denied")
                raise
            if self._state.mode != "observe":
                raise AuthorityDenied("Disable the current authority mode before arming another")
            now = self._utc_now()
            self._state = AuthorityState(
                mode=mode,
                status="active",
                owner=username,
                session_id=session_id,
                hosts=tuple(sorted(set(hosts))),
                capabilities=tuple(sorted(set(capabilities))),
                action_budget=action_budget,
                concurrency=concurrency,
                armed_at=now.isoformat(),
                expires_at=(now + timedelta(minutes=duration_minutes)).isoformat(),
            )
            self._record("automation_mode_armed", username, session_id, asdict(self._state))
            return asdict(self._state)

    def pause(self, username: str, session_id: str) -> dict[str, object]:
        with self._lock:
            self._require_owner(username, session_id)
            if self._state.status != "active":
                raise AuthorityDenied("Authority mode is not active")
            self._state = AuthorityState(**{**asdict(self._state), "status": "paused"})
            self._record("automation_mode_paused", username, session_id, {})
            return asdict(self._state)

    def resume(self, username: str, session_id: str) -> dict[str, object]:
        with self._lock:
            self._expire_if_needed()
            self._require_owner(username, session_id)
            if self._state.status != "paused":
                raise AuthorityDenied("Authority mode is not paused")
            self._state = AuthorityState(**{**asdict(self._state), "status": "active"})
            self._record("automation_mode_resumed", username, session_id, {})
            return asdict(self._state)

    def stop(self, username: str, session_id: str, *, emergency: bool = False) -> dict[str, object]:
        with self._lock:
            if self._state.mode == "observe":
                return asdict(self._state)
            if not emergency:
                self._require_owner(username, session_id)
            previous = asdict(self._state)
            self._state = AuthorityState()
            self._record(
                "automation_emergency_stop" if emergency else "automation_mode_stopped",
                username, session_id, previous,
            )
            return asdict(self._state)

    def stop_session(self, username: str, session_id: str) -> None:
        with self._lock:
            if self._state.session_id == session_id:
                previous = asdict(self._state)
                self._state = AuthorityState()
                self._record("automation_mode_logout_reset", username, session_id, previous)

    def authorize(self, username: str, session_id: str, host: str, capability: str) -> None:
        """Recheck active authority immediately before a mutation or its preview."""
        with self._lock:
            self._expire_if_needed()
            self._require_owner(username, session_id)
            if self._state.status != "active":
                raise AuthorityDenied("Authority mode is not active")
            if host not in self._state.hosts or capability not in self._state.capabilities:
                raise AuthorityDenied("Host or capability is outside the armed authority scope")
            if self._state.mode == "autonomous_lab" and (
                self._hosts.get(host) is None
                or self._hosts[host].environment not in AUTONOMOUS_ENVIRONMENTS
            ):
                self._reset("automation_environment_became_ineligible")
                raise AuthorityDenied("Host is no longer eligible for Autonomous Lab")

    def _validate_arm(self, mode: str, hosts: Sequence[str], capabilities: Sequence[str],
                      duration: int, budget: int, concurrency: int) -> None:
        if mode not in {"guided", "autonomous_lab"}:
            raise AuthorityDenied("Only Guided or Autonomous Lab can be armed")
        if not 1 <= len(hosts) <= 30 or len(set(hosts)) != len(hosts):
            raise AuthorityDenied("Select between 1 and 30 unique hosts")
        unknown = set(hosts) - self._hosts.keys()
        if unknown:
            raise AuthorityDenied("Unknown or unapproved host in authority scope")
        if mode == "autonomous_lab" and any(
            self._hosts[name].environment not in AUTONOMOUS_ENVIRONMENTS for name in hosts
        ):
            raise AuthorityDenied("Autonomous Lab only permits development or disposable-lab hosts")
        if not capabilities or not set(capabilities) <= CAPABILITIES:
            raise AuthorityDenied("One or more capabilities are unavailable")
        if not 15 <= duration <= 60:
            raise AuthorityDenied("Duration must be between 15 and 60 minutes")
        if not 1 <= budget <= 50:
            raise AuthorityDenied("Action budget must be between 1 and 50")
        if not 1 <= concurrency <= 3 or concurrency > len(hosts):
            raise AuthorityDenied("Concurrency must be between 1 and 3 and not exceed host count")

    def _require_owner(self, username: str, session_id: str) -> None:
        if self._state.owner != username or self._state.session_id != session_id:
            raise AuthorityDenied("Authority mode belongs to another authenticated session")

    def _expire_if_needed(self) -> None:
        if self._state.expires_at and self._utc_now() >= datetime.fromisoformat(self._state.expires_at):
            previous = asdict(self._state)
            self._state = AuthorityState()
            self._record(
                "automation_mode_expired",
                str(previous["owner"]),
                str(previous["session_id"]),
                previous,
            )

    def _reset(self, reason: str) -> None:
        previous = asdict(self._state)
        self._state = AuthorityState()
        self._record(reason, str(previous["owner"]), str(previous["session_id"]), previous)

    def _record(self, kind: str, username: str, session_id: str,
                parameters: Mapping[str, object], status: str = "success") -> None:
        self._audit.append(AuditEvent(
            request_id=str(uuid4()), session_id=session_id, target_host="authority",
            tool_name=kind, parameters={"operator": username, **parameters}, command=(),
            status=status,
        ))

    def _utc_now(self) -> datetime:
        value = self._now()
        return value if value.tzinfo else value.replace(tzinfo=UTC)
