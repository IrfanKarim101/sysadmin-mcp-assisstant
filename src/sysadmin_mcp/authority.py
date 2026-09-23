"""Fail-closed, in-memory authority modes for supervised lab automation."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from uuid import uuid4

from .audit import AuditEvent, AuditSink
from .config import HostConfig

MODES = frozenset({"observe", "guided", "autonomous_lab", "dynamic_sandbox"})
CAPABILITIES = frozenset({"backups", "managed_files", "packages", "services", "dynamic_scripts", "host_scripts"})
AUTONOMOUS_RECIPES = frozenset({"nginx_install_configure@1"})
AUTONOMOUS_ENVIRONMENTS = frozenset({"development", "disposable_lab"})


class AuthorityDenied(ValueError):
    """An authority transition was rejected by deterministic policy."""


@dataclass(frozen=True)
class AuthorityState:
    generation_id: str | None = None
    mode: str = "observe"
    status: str = "inactive"
    owner: str | None = None
    session_id: str | None = None
    hosts: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    recipe_ids: tuple[str, ...] = ()
    action_budget: int = 0
    actions_used: int = 0
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
        recipe_ids: Sequence[str] = (),
    ) -> dict[str, object]:
        with self._lock:
            try:
                self._validate_arm(
                    mode, hosts, capabilities, duration_minutes, action_budget, concurrency,
                    recipe_ids,
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
                generation_id=str(uuid4()),
                mode=mode,
                status="active",
                owner=username,
                session_id=session_id,
                hosts=tuple(sorted(set(hosts))),
                capabilities=tuple(sorted(set(capabilities))),
                recipe_ids=tuple(sorted(set(recipe_ids))),
                action_budget=action_budget,
                actions_used=0,
                concurrency=concurrency,
                armed_at=now.isoformat(),
                expires_at=(now + timedelta(minutes=duration_minutes)).isoformat(),
            )
            try:
                self._record("automation_mode_armed", username, session_id, asdict(self._state))
            except Exception:
                self._state = AuthorityState()
                raise
            return asdict(self._state)

    def authorize_recipe(self, username: str, session_id: str, host: str,
                         recipe_id: str) -> None:
        with self._lock:
            self._expire_if_needed()
            self._require_owner(username, session_id)
            if self._state.mode != "autonomous_lab" or self._state.status != "active":
                raise AuthorityDenied("An active Autonomous Lab session is required")
            if host not in self._state.hosts or recipe_id not in self._state.recipe_ids:
                raise AuthorityDenied("Host or recipe is outside the armed authority scope")
            if self._hosts.get(host) is None or (
                self._hosts[host].environment not in AUTONOMOUS_ENVIRONMENTS
            ):
                self._reset("automation_environment_became_ineligible")
                raise AuthorityDenied("Host is no longer eligible for Autonomous Lab")

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
            if self._state.mode in {"autonomous_lab", "dynamic_sandbox"} and (
                self._hosts.get(host) is None
                or self._hosts[host].environment not in AUTONOMOUS_ENVIRONMENTS
            ):
                self._reset("automation_environment_became_ineligible")
                raise AuthorityDenied("Host is no longer eligible for Autonomous Lab")

    def authorize_plan(self, username: str, session_id: str, hosts: Sequence[str],
                       capabilities: Sequence[str], action_count: int) -> None:
        with self._lock:
            self._expire_if_needed()
            self._require_owner(username, session_id)
            if self._state.status != "active":
                raise AuthorityDenied("Authority mode is not active")
            if not set(hosts) <= set(self._state.hosts):
                raise AuthorityDenied("Plan includes a host outside the armed scope")
            if not set(capabilities) <= set(self._state.capabilities):
                raise AuthorityDenied("Plan includes a capability outside the armed scope")
            if action_count < 1 or self._state.actions_used + action_count > self._state.action_budget:
                raise AuthorityDenied("Plan exceeds the remaining authority action budget")
            if self._state.mode in {"autonomous_lab", "dynamic_sandbox"} and any(
                self._hosts[name].environment not in AUTONOMOUS_ENVIRONMENTS for name in hosts
            ):
                raise AuthorityDenied("Plan host is not eligible for Autonomous Lab")

    def consume(self, username: str, session_id: str, action_count: int) -> None:
        with self._lock:
            self._expire_if_needed()
            self._require_owner(username, session_id)
            if self._state.status != "active":
                raise AuthorityDenied("Authority mode is not active")
            if action_count < 1 or self._state.actions_used + action_count > self._state.action_budget:
                raise AuthorityDenied("Action budget is exhausted")
            self._state = AuthorityState(**{
                **asdict(self._state), "actions_used": self._state.actions_used + action_count,
            })

    def _validate_arm(self, mode: str, hosts: Sequence[str], capabilities: Sequence[str],
                      duration: int, budget: int, concurrency: int,
                      recipe_ids: Sequence[str]) -> None:
        if mode not in {"guided", "autonomous_lab", "dynamic_sandbox"}:
            raise AuthorityDenied("Unsupported authority mode")
        if not 1 <= len(hosts) <= 30 or len(set(hosts)) != len(hosts):
            raise AuthorityDenied("Select between 1 and 30 unique hosts")
        unknown = set(hosts) - self._hosts.keys()
        if unknown:
            raise AuthorityDenied("Unknown or unapproved host in authority scope")
        if mode in {"autonomous_lab", "dynamic_sandbox"} and any(
            self._hosts[name].environment not in AUTONOMOUS_ENVIRONMENTS for name in hosts
        ):
            raise AuthorityDenied("Autonomous Lab only permits development or disposable-lab hosts")
        if not capabilities or not set(capabilities) <= CAPABILITIES:
            raise AuthorityDenied("One or more capabilities are unavailable")
        if "host_scripts" in capabilities and any(
            self._hosts[name].environment not in AUTONOMOUS_ENVIRONMENTS for name in hosts
        ):
            raise AuthorityDenied("Host scripts require development or disposable-lab hosts")
        if mode == "dynamic_sandbox" and set(capabilities) != {"dynamic_scripts"}:
            raise AuthorityDenied("Dynamic sandbox only permits isolated dynamic scripts")
        if mode != "dynamic_sandbox" and "dynamic_scripts" in capabilities:
            raise AuthorityDenied("Dynamic scripts require Dynamic sandbox mode")
        if len(set(recipe_ids)) != len(recipe_ids) or not set(recipe_ids) <= AUTONOMOUS_RECIPES:
            raise AuthorityDenied("One or more autonomous recipes are unavailable")
        if recipe_ids and mode != "autonomous_lab":
            raise AuthorityDenied("Recipes can only be armed in Autonomous Lab")
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
