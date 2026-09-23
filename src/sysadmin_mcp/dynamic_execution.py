"""Reviewed, one-use Python jobs for a separate rootless remote sandbox."""
from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .audit import AuditEvent
from .authority import AuthorityDenied


class DynamicDenied(ValueError):
    pass


class Scripts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    script: str = Field(min_length=1, max_length=16_000)
    verification: str = Field(min_length=1, max_length=16_000)
    timeout_seconds: int = Field(default=30, ge=1, le=120, strict=True)

    @field_validator("script", "verification")
    @classmethod
    def syntax(cls, value: str) -> str:
        # Syntax validation is NOT a security sandbox. Isolation is host-enforced.
        if len(value.encode("utf-8")) > 32_000 or "\x00" in value:
            raise ValueError("Script exceeds byte bounds or contains NUL")
        try:
            compile(value, "<reviewed-script>", "exec")
        except (SyntaxError, ValueError, RecursionError) as error:
            raise ValueError("Invalid Python syntax") from error
        return value


class DraftRequest(Scripts):
    host: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    title: str = Field(min_length=1, max_length=120)


class HostScripts(Scripts):
    timeout_seconds: int = Field(default=120, ge=1, le=900, strict=True)


class HostDraftRequest(HostScripts):
    host: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    title: str = Field(min_length=1, max_length=120)


class GenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    task: str = Field(min_length=1, max_length=4_000)
    provider: Literal["openai", "gemini", "local"] = "openai"


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    password: str = Field(min_length=1, max_length=256)


class Output(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exit_status: int = Field(strict=True)
    stdout: str = Field(max_length=65_536)
    stderr: str = Field(max_length=65_536)
    truncated: bool = Field(strict=True)


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    passed: bool = Field(strict=True)


class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    checks: Annotated[list[Check], Field(min_length=1, max_length=50)]


class SandboxResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution: Output
    verification: Output | None = None


def verified(result: SandboxResult) -> bool:
    if result.execution.exit_status != 0 or result.execution.truncated:
        return False
    output = result.verification
    if output is None or output.exit_status != 0 or output.truncated:
        return False
    try:
        verdict = Verdict.model_validate_json(output.stdout)
    except ValueError:
        return False
    return all(check.passed for check in verdict.checks)


class DynamicJobs:
    scripts_model = Scripts
    capability = "dynamic_scripts"
    modes = frozenset({"dynamic_sandbox"})
    sandbox = True
    def __init__(self, path: Path, authority, audit, runner=None):
        self.path, self.authority, self.audit, self.runner = path, authority, audit, runner
        with closing(self._connect()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS dynamic_jobs (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, session TEXT NOT NULL,
                host TEXT NOT NULL, lease TEXT NOT NULL, expires TEXT NOT NULL,
                title TEXT NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL,
                state TEXT NOT NULL, result TEXT NOT NULL DEFAULT '{}')""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(dynamic_jobs)")}
            if "approval_required" not in columns:
                db.execute("ALTER TABLE dynamic_jobs ADD COLUMN approval_required INTEGER NOT NULL DEFAULT 0")
            # Restart never automatically resumes or replays remote jobs.
            db.execute("UPDATE dynamic_jobs SET state='interrupted' WHERE state='running'")

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def authorized(self, username: str, session: str, host: str) -> dict[str, Any]:
        self.authority.authorize(username, session, host, self.capability)
        state = self.authority.current()
        if state["mode"] not in self.modes:
            raise AuthorityDenied("Arm the appropriate script execution mode first")
        return state

    def create(self, username: str, session: str, body: DraftRequest, *, approval_required=False):
        state = self.authorized(username, session, body.host)
        payload = self.scripts_model(**body.model_dump(exclude={"host", "title"})).model_dump_json()
        digest = hashlib.sha256((body.host + "\n" + payload).encode()).hexdigest()
        job_id = str(uuid4())
        expires = (datetime.now(UTC) + timedelta(minutes=10)).isoformat()
        self._audit(job_id, session, body.host, "dynamic_prepared", "attempted", digest)
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM dynamic_jobs WHERE session=?", (session,)).fetchone()[0] >= 100:
                raise DynamicDenied("Session job limit reached")
            db.execute("INSERT INTO dynamic_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       (job_id, username, session, body.host, state["generation_id"], expires,
                        body.title, payload, digest, "prepared", "{}", int(approval_required)))
        return self.get(username, session, job_id)

    def get(self, username: str, session: str, job_id: str):
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM dynamic_jobs WHERE id=? AND owner=? AND session=?",
                             (job_id, username, session)).fetchone()
        if row is None:
            raise DynamicDenied("Job not found for this authenticated session")
        result = dict(row)
        for field in ("owner", "session", "lease"):
            result.pop(field)
        result["scripts"] = json.loads(result.pop("payload"))
        result["result"] = json.loads(result["result"])
        return result

    def _audit(self, job, session, host, tool, status, digest):
        self.audit.append(AuditEvent(request_id=job, session_id=session, target_host=host,
                                    tool_name=tool, status=status, command=(),
                                    parameters={"digest": digest, "sandbox": self.sandbox}))

    def _finish(self, job, state, result):
        with closing(self._connect()) as db, db:
            db.execute("UPDATE dynamic_jobs SET state=?, result=? WHERE id=?",
                       (state, json.dumps(result), job))

    async def run(self, username: str, session: str, job_id: str, digest: str, *, user_approved=False):
        job = self.get(username, session, job_id)
        state = self.authorized(username, session, job["host"])
        if self.runner is None:
            raise DynamicDenied("Remote sandbox transport is not configured")
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM dynamic_jobs WHERE id=?", (job_id,)).fetchone()
            if row["approval_required"] and not user_approved:
                raise DynamicDenied("This installation requires operator review and approval in the web UI")
            if row["state"] != "prepared" or row["digest"] != digest:
                raise DynamicDenied("Job was already used or the reviewed script changed")
            if row["lease"] != state["generation_id"] or datetime.fromisoformat(row["expires"]) <= datetime.now(UTC):
                raise DynamicDenied("Job review expired; prepare a new job")
            running = db.execute("SELECT host FROM dynamic_jobs WHERE state='running'").fetchall()
            if len(running) >= state["concurrency"] or any(r["host"] == job["host"] for r in running):
                raise DynamicDenied("Concurrency limit or host lock is active")
            db.execute("UPDATE dynamic_jobs SET state='running' WHERE id=?", (job_id,))
        task = None
        try:
            self.authority.consume(username, session, 1)
            # Audit uses its own SQLite connection; never call it while holding
            # the job DB write transaction. No transport starts before commit.
            self._audit(job_id, session, job["host"], "dynamic_execute", "attempted", digest)
            if self.authorized(username, session, job["host"])["generation_id"] != state["generation_id"]:
                raise AuthorityDenied("Authority was replaced")
            if row["approval_required"]:
                self._audit(job_id, session, job["host"], "dynamic_approved", "success", digest)
            scripts = self.scripts_model.model_validate(job["scripts"])
            task = asyncio.create_task(self.runner(job["host"], scripts))
            async with asyncio.timeout(scripts.timeout_seconds + 30):
                while not task.done():
                    await asyncio.wait({task}, timeout=0.25)
                    if self.authorized(username, session, job["host"])["generation_id"] != state["generation_id"]:
                        raise AuthorityDenied("Authority was replaced")
                result = SandboxResult.model_validate(await task)
            passed = verified(result)
            self._audit(job_id, session, job["host"], "dynamic_completed",
                        "success" if passed else "error", digest)
            self._finish(job_id, "verified" if passed else "verification_failed", result.model_dump())
        except BaseException as error:
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            self._finish(job_id, "interrupted" if isinstance(error, asyncio.CancelledError) else "failed",
                         {"error": type(error).__name__, "message": ("Execution timed out; inspect the VM before retrying." if isinstance(error, TimeoutError) else
                                      "Authority was stopped, expired, or exhausted." if isinstance(error, AuthorityDenied) else
                                      "Remote execution failed. Check SSH connectivity, helper provisioning and account permissions; inspect the VM before retrying.")})
            self._audit(job_id, session, job["host"], "dynamic_failed", "error", digest)
            if isinstance(error, asyncio.CancelledError):
                raise
        return self.get(username, session, job_id)
