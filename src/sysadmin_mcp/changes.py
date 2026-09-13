"""Persistent, simulation-only change transactions for Phase 16."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .audit import AuditEvent, AuditSink
from .authority import AuthorityDenied, AuthorityService
from .recovery import RecoveryDenied, RecoveryStore
from .managed_files import ManagedFileDenied, ManagedFilePlanner
from .packages import PackageDenied, PackagePlanner
from .services import ServiceDenied, ServicePlanner

APPROVAL_TTL = timedelta(minutes=5)
ACTION_CAPABILITIES = {
    "write_managed_file": "managed_files", "install_package": "packages",
    "update_package": "packages", "enable_service": "services",
    "disable_service": "services", "reload_service": "services",
    "restart_service": "services", "run_backup": "backups",
}
TERMINAL_STATES = frozenset({"accepted", "rolled_back", "cancelled", "failed"})


class ChangeDenied(ValueError):
    pass


class ChangeAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    action: str = Field(max_length=32)
    host: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    target: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@/-]{0,127}$")
    value: str | None = Field(default=None, max_length=32_000)
    version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}$")

    @model_validator(mode="after")
    def supported(self):
        if self.action not in ACTION_CAPABILITIES:
            raise ValueError("unsupported change action")
        if self.action == "write_managed_file" and not self.value:
            raise ValueError("managed file simulation requires proposed content")
        if self.action != "write_managed_file" and self.value is not None:
            raise ValueError("value is only accepted for managed file simulation")
        if self.action not in {"install_package", "update_package"} and self.version is not None:
            raise ValueError("version is only accepted for package actions")
        return self


class ChangeTransactionService:
    def __init__(self, path: Path, authority: AuthorityService, audit: AuditSink,
                 *, now: Callable[[], datetime] | None = None,
                 recovery: RecoveryStore | None = None,
                 managed_files: ManagedFilePlanner | None = None,
                 packages: PackagePlanner | None = None,
                 services: ServicePlanner | None = None) -> None:
        self.path, self.authority, self.audit = path, authority, audit
        self._now = now or (lambda: datetime.now(UTC))
        self.recovery = recovery or RecoveryStore(path, audit, now=self._now)
        self.managed_files = managed_files
        self.packages = packages
        self.services = services
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS change_transactions (
              id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              username TEXT NOT NULL, session_id TEXT NOT NULL, title TEXT NOT NULL,
              state TEXT NOT NULL, actions TEXT NOT NULL, plan_hash TEXT NOT NULL,
              preview TEXT, diff_hash TEXT, approval_hash TEXT, approval_expires_at TEXT,
              evidence TEXT NOT NULL DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_change_transactions_updated
              ON change_transactions(updated_at DESC);
            """)

    def create(self, username: str, session_id: str, title: str,
               actions: Sequence[ChangeAction]) -> dict[str, object]:
        if not title.strip() or len(title) > 120 or not 1 <= len(actions) <= 50:
            raise ChangeDenied("Title or action count is outside policy")
        hosts = sorted({item.host for item in actions})
        capabilities = sorted({ACTION_CAPABILITIES[item.action] for item in actions})
        self.authority.authorize_plan(username, session_id, hosts, capabilities, len(actions))
        validated = _validated_files(actions)
        for item in actions:
            if item.action == "write_managed_file":
                if self.managed_files is None:
                    raise ChangeDenied("Managed-file policy is unavailable")
                self.managed_files.preview(item.host, item.target, item.value or "")
            if item.action in {"install_package", "update_package"}:
                if self.packages is None:
                    raise ChangeDenied("Package policy is unavailable")
                self.packages.preview(item.action, item.host, item.target, item.version)
            if item.action in {"enable_service", "disable_service", "reload_service", "restart_service"}:
                if self.services is None:
                    raise ChangeDenied("Service policy is unavailable")
                self.services.preview(item.action, item.host, item.target, validated.get(item.host, ()))
        encoded = _canonical([item.model_dump() for item in actions])
        now, transaction_id = self._utc_now(), str(uuid4())
        with self._connect() as db:
            db.execute("""INSERT INTO change_transactions
              (id,created_at,updated_at,username,session_id,title,state,actions,plan_hash)
              VALUES (?,?,?,?,?,?, 'planned', ?,?)""",
              (transaction_id, now.isoformat(), now.isoformat(), username, session_id,
               title.strip(), encoded, _digest(encoded)))
        self._audit(transaction_id, session_id, username, "change_plan_created",
                    {"hosts": hosts, "capabilities": capabilities, "actions": len(actions)})
        return self.get(transaction_id, username, session_id)

    def preview(self, transaction_id: str, username: str, session_id: str) -> dict[str, object]:
        row = self._owned(transaction_id, username, session_id)
        if row["state"] not in {"planned", "previewed"}:
            raise ChangeDenied("Only a planned transaction can be previewed")
        actions = json.loads(row["actions"])
        validated = _validated_files([ChangeAction.model_validate(item) for item in actions])
        snapshots = self.recovery.capture(transaction_id, actions, username, session_id)
        snapshots_by_index = {item["action_index"]: item for item in snapshots}
        preview = []
        for index, action in enumerate(actions):
            item = {"index": index, "effect": _effect(action),
                    "service_impact": _service_impact(action),
                    "validation": _validation(action),
                    "rollback_strategy": _rollback_strategy(action),
                    "content_sha256": _content_hash(action)}
            if action["action"] == "write_managed_file":
                if self.managed_files is None:
                    raise ChangeDenied("Managed-file policy is unavailable")
                item["managed_file"] = self.managed_files.preview(
                    str(action["host"]), str(action["target"]), str(action["value"])
                )
            if action["action"] in {"install_package", "update_package"}:
                if self.packages is None:
                    raise ChangeDenied("Package policy is unavailable")
                item["package"] = self.packages.preview(
                    str(action["action"]), str(action["host"]), str(action["target"]),
                    str(action["version"]) if action.get("version") else None,
                )
            if action["action"] in {"enable_service", "disable_service", "reload_service", "restart_service"}:
                if self.services is None:
                    raise ChangeDenied("Service policy is unavailable")
                item["service"] = self.services.preview(
                    str(action["action"]), str(action["host"]), str(action["target"]),
                    validated.get(str(action["host"]), ()),
                )
            if index in snapshots_by_index:
                item["recovery_snapshot"] = snapshots_by_index[index]
            preview.append(item)
        encoded = _canonical(preview)
        self._update(transaction_id, state="previewed", preview=encoded,
                     diff_hash=_digest(encoded), approval_hash=None, approval_expires_at=None)
        self._audit(transaction_id, session_id, username, "change_preview_created",
                    {"plan_hash": row["plan_hash"], "diff_hash": _digest(encoded)})
        return self.get(transaction_id, username, session_id)

    def approve(self, transaction_id: str, username: str, session_id: str) -> dict[str, object]:
        row = self._owned(transaction_id, username, session_id)
        if row["state"] != "previewed" or not row["diff_hash"]:
            raise ChangeDenied("Preview must be reviewed before approval")
        preview = json.loads(row["preview"])
        if any(item.get("managed_file", {}).get("diff_truncated") for item in preview):
            raise ChangeDenied("A managed-file diff exceeds review bounds")
        token = secrets.token_urlsafe(32)
        expires = self._utc_now() + APPROVAL_TTL
        self._update(transaction_id, state="approved", approval_hash=_digest(token),
                     approval_expires_at=expires.isoformat())
        self._audit(transaction_id, session_id, username, "change_plan_approved",
                    {"plan_hash": row["plan_hash"], "diff_hash": row["diff_hash"]})
        return {**self.get(transaction_id, username, session_id),
                "approval_token": token, "approval_expires_at": expires.isoformat()}

    def simulate(self, transaction_id: str, token: str, username: str,
                 session_id: str) -> dict[str, object]:
        row = self._owned(transaction_id, username, session_id)
        if row["state"] != "approved" or not row["approval_hash"] or not secrets.compare_digest(
            row["approval_hash"], _digest(token)
        ):
            raise ChangeDenied("Approval is invalid, changed, or already used")
        if self._utc_now() >= datetime.fromisoformat(row["approval_expires_at"]):
            raise ChangeDenied("Approval expired; preview and approve again")
        actions = [ChangeAction.model_validate(item) for item in json.loads(row["actions"])]
        hosts = sorted({item.host for item in actions})
        capabilities = sorted({ACTION_CAPABILITIES[item.action] for item in actions})
        self.authority.authorize_plan(username, session_id, hosts, capabilities, len(actions))
        file_plans = []
        package_plans = []
        service_plans = []
        validated = _validated_files(actions)
        for item in actions:
            if item.action == "write_managed_file":
                if self.managed_files is None:
                    raise ChangeDenied("Managed-file policy is unavailable")
                file_plans.append(self.managed_files.preview(item.host, item.target, item.value or ""))
            if item.action in {"install_package", "update_package"}:
                if self.packages is None:
                    raise ChangeDenied("Package policy is unavailable")
                package_plans.append({"host": item.host, **self.packages.preview(
                    item.action, item.host, item.target, item.version
                )})
            if item.action in {"enable_service", "disable_service", "reload_service", "restart_service"}:
                if self.services is None:
                    raise ChangeDenied("Service policy is unavailable")
                service_plans.append(self.services.preview(
                    item.action, item.host, item.target, validated.get(item.host, ())
                ))
        snapshots = self.recovery.capture(
            transaction_id, [item.model_dump() for item in actions], username, session_id
        )
        self.recovery.verify_required(
            transaction_id, [item.model_dump() for item in actions]
        )
        self.authority.consume(username, session_id, len(actions))
        evidence = []
        for state, stage in (
            ("backed_up", "backup"), ("applying", "apply"),
            ("validating", "validate"), ("verifying", "verify"),
        ):
            entry: dict[str, object] = {
                "stage": stage, "status": "simulated", "remote_mutation": False
            }
            if stage == "backup":
                entry["snapshots"] = snapshots
            if stage in {"apply", "validate"} and file_plans:
                entry["managed_files"] = file_plans
            if stage in {"apply", "verify"} and package_plans:
                entry["packages"] = package_plans
                entry["rollout"] = self.packages.rollout(package_plans) if self.packages else None
            if stage in {"validate", "verify"} and service_plans:
                entry["services"] = service_plans
                if stage == "verify" and self.services:
                    entry["service_outcomes"] = [self.services.evaluate(
                        plan, [{"passed": True} for _ in plan["verification_checks"]]
                    ) for plan in service_plans]
            evidence.append(entry)
            self._update(transaction_id, state=state, evidence=_canonical(evidence),
                         approval_hash=None, approval_expires_at=None)
            self._audit(transaction_id, session_id, username,
                        f"change_{stage}_simulated", {"remote_mutation": False})
        self._audit(transaction_id, session_id, username, "change_simulation_completed",
                    {"actions": len(actions), "remote_mutation": False})
        return self.get(transaction_id, username, session_id)

    def requires_material_approval(self, transaction_id: str, username: str,
                                   session_id: str) -> bool:
        row = self._owned(transaction_id, username, session_id)
        if row["state"] != "approved":
            raise ChangeDenied("Transaction is not ready for activation")
        return any(item.get("service", {}).get("material_approval_required")
                   for item in json.loads(row["preview"] or "[]"))

    def accept(self, transaction_id: str, username: str, session_id: str) -> dict[str, object]:
        row = self._owned(transaction_id, username, session_id)
        if row["state"] != "verifying":
            raise ChangeDenied("Only a verified simulation can be accepted")
        self._update(transaction_id, state="accepted")
        self._audit(transaction_id, session_id, username, "change_outcome_accepted", {})
        return self.get(transaction_id, username, session_id)

    def rollback(self, transaction_id: str, username: str, session_id: str) -> dict[str, object]:
        row = self._owned(transaction_id, username, session_id)
        if row["state"] not in {"approved", "verifying", "failed"}:
            raise ChangeDenied("Transaction is not eligible for rollback")
        evidence = json.loads(row["evidence"])
        restored = self.recovery.restore(transaction_id, username, session_id)
        evidence.append({"stage": "rollback", "status": "simulated",
                         "remote_mutation": False, "snapshots": restored,
                         "post_rollback_check": "simulated_passed"})
        self._update(transaction_id, state="rolled_back", evidence=_canonical(evidence),
                     approval_hash=None, approval_expires_at=None)
        self._audit(transaction_id, session_id, username, "change_rollback_simulated", {})
        return self.get(transaction_id, username, session_id)

    def cancel(self, transaction_id: str, username: str, session_id: str) -> dict[str, object]:
        row = self._owned(transaction_id, username, session_id)
        if row["state"] in TERMINAL_STATES or row["state"] == "verifying":
            raise ChangeDenied("Transaction can no longer be cancelled")
        self._update(transaction_id, state="cancelled", approval_hash=None, approval_expires_at=None)
        self._audit(transaction_id, session_id, username, "change_plan_cancelled", {})
        return self.get(transaction_id, username, session_id)

    def get(self, transaction_id: str, username: str, session_id: str) -> dict[str, object]:
        row = self._owned(transaction_id, username, session_id)
        return _public(row)

    def list(self, username: str, session_id: str, limit: int = 50) -> list[dict[str, object]]:
        if not 1 <= limit <= 100:
            raise ChangeDenied("Limit must be between 1 and 100")
        with self._connect() as db:
            rows = db.execute("""SELECT * FROM change_transactions
              WHERE username=? AND session_id=? ORDER BY updated_at DESC LIMIT ?""",
              (username, session_id, limit)).fetchall()
        return [_public(row) for row in rows]

    def _owned(self, transaction_id: str, username: str, session_id: str) -> sqlite3.Row:
        try:
            normalized = str(UUID(transaction_id))
        except (ValueError, TypeError, AttributeError) as error:
            raise ChangeDenied("Invalid change transaction ID") from error
        with self._connect() as db:
            row = db.execute("SELECT * FROM change_transactions WHERE id=?", (normalized,)).fetchone()
        if row is None or row["username"] != username or row["session_id"] != session_id:
            raise ChangeDenied("Unknown change transaction")
        return row

    def _update(self, transaction_id: str, **values: object) -> None:
        allowed = {"state", "preview", "diff_hash", "approval_hash", "approval_expires_at", "evidence"}
        if not values or not set(values) <= allowed:
            raise ChangeDenied("Invalid transaction update")
        values["updated_at"] = self._utc_now().isoformat()
        with self._connect() as db:
            db.execute(
                f"UPDATE change_transactions SET {', '.join(f'{key}=?' for key in values)} WHERE id=?",
                (*values.values(), transaction_id),
            )

    def _audit(self, transaction_id: str, session_id: str, username: str,
               event: str, parameters: Mapping[str, object]) -> None:
        self.audit.append(AuditEvent(
            request_id=str(uuid4()), session_id=session_id, target_host="change-plan",
            tool_name=event, parameters={"transaction_id": transaction_id,
                                         "operator": username, **parameters},
            command=(), status="success",
        ))

    def _utc_now(self) -> datetime:
        value = self._now()
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        return db


def _effect(action: Mapping[str, object]) -> str:
    verb = str(action["action"]).replace("_", " ")
    return f"SIMULATION ONLY: {verb} {action['target']} on {action['host']}"


def _validated_files(actions: Sequence[ChangeAction]) -> dict[str, tuple[str, ...]]:
    result: dict[str, list[str]] = {}
    for item in actions:
        if item.action == "write_managed_file":
            result.setdefault(item.host, []).append(item.target)
    return {host: tuple(ids) for host, ids in result.items()}


def _content_hash(action: Mapping[str, object]) -> str | None:
    value = action.get("value")
    return hashlib.sha256(str(value).encode()).hexdigest() if value is not None else None


def _service_impact(action: Mapping[str, object]) -> str:
    return "brief service interruption possible" if action["action"] == "restart_service" else "none simulated"


def _validation(action: Mapping[str, object]) -> str:
    kind = str(action["action"])
    if kind == "write_managed_file":
        return "validate managed content against its registered policy"
    if kind in {"install_package", "update_package"}:
        return "verify package state through the typed package adapter"
    if kind == "run_backup":
        return "verify backup artifact reference and checksum"
    return "verify service state through the typed service adapter"


def _rollback_strategy(action: Mapping[str, object]) -> str:
    kind = str(action["action"])
    if kind == "write_managed_file":
        return "restore the pre-change managed-file backup"
    if kind in {"install_package", "update_package"}:
        return "restore the captured package-state baseline"
    if kind == "run_backup":
        return "no host rollback; discard the simulated artifact"
    return "restore the captured service enablement and runtime state"


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _public(row: Mapping[str, object]) -> dict[str, object]:
        return {
        "id": row["id"], "created_at": row["created_at"], "updated_at": row["updated_at"],
        "title": row["title"], "state": row["state"],
        "actions": json.loads(str(row["actions"])), "plan_hash": row["plan_hash"],
        "preview": json.loads(str(row["preview"])) if row["preview"] else None,
        "diff_hash": row["diff_hash"],
        "approval_expires_at": row["approval_expires_at"],
        "rollback_available": row["state"] in {"approved", "verifying", "failed"},
        "evidence": json.loads(str(row["evidence"])),
    }
