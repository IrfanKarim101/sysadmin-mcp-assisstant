import asyncio
import json

import pytest
from pydantic import ValidationError
from test_authority import AuditCapture, arm, host

from sysadmin_mcp.authority import AuthorityDenied, AuthorityService
from sysadmin_mcp.dynamic_execution import (
    DraftRequest,
    DynamicDenied,
    DynamicJobs,
    SandboxResult,
    Scripts,
    verified,
)


def result(checks=None, exit_status=0):
    output = {"exit_status": exit_status, "stdout": "created", "stderr": "", "truncated": False}
    return {"execution": output, "verification": {**output, "stdout": json.dumps(
        {"checks": checks if checks is not None else [{"name": "content", "passed": True}]})}}


def setup(tmp_path, runner=None):
    audit = AuditCapture()
    authority = AuthorityService({"lab": host("lab", "development"),
                                  "prod": host("prod", "production")}, audit)
    arm(authority, mode="dynamic_sandbox", capabilities=["dynamic_scripts"])
    jobs = DynamicJobs(tmp_path / "jobs.db", authority, audit, runner)
    return jobs, authority, audit


def draft(jobs):
    return jobs.create("admin", "session-a", DraftRequest(
        host="lab", title="test", script="print('hello')", verification="print('checks')"))


def test_dynamic_scope_is_separate_and_lab_only(tmp_path):
    jobs, authority, _ = setup(tmp_path)
    authority.stop("admin", "session-a")
    for values in [{"hosts": ["prod"], "mode": "dynamic_sandbox", "capabilities": ["dynamic_scripts"]},
                   {"mode": "guided", "capabilities": ["dynamic_scripts"]},
                   {"mode": "dynamic_sandbox", "capabilities": ["services"]}]:
        with pytest.raises(AuthorityDenied):
            arm(authority, **values)
    with pytest.raises(AuthorityDenied):
        draft(jobs)


@pytest.mark.asyncio
async def test_success_is_one_use_owner_scoped_and_audited(tmp_path):
    calls = []
    async def runner(host_name, scripts):
        calls.append(host_name)
        return result()
    jobs, authority, audit = setup(tmp_path, runner)
    job = draft(jobs)
    with pytest.raises(DynamicDenied):
        jobs.get("admin", "other-session", job["id"])
    with pytest.raises(DynamicDenied):
        await jobs.run("admin", "session-a", job["id"], "0" * 64)
    completed = await jobs.run("admin", "session-a", job["id"], job["digest"])
    assert completed["state"] == "verified"
    with pytest.raises(DynamicDenied):
        await jobs.run("admin", "session-a", job["id"], job["digest"])
    assert calls == ["lab"]
    assert authority.current()["actions_used"] == 1
    assert audit.events[-1].tool_name == "dynamic_completed"


@pytest.mark.parametrize("checks", [[], [{"name": "x", "passed": False}], [{"name": "x", "passed": "true"}]])
def test_verification_does_not_accept_exit_code_alone(checks):
    assert not verified(SandboxResult.model_validate(result(checks)))


def test_truncation_failed_execution_and_missing_verifier_fail():
    assert not verified(SandboxResult.model_validate(result(exit_status=1)))
    data = result()
    data["verification"] = None
    assert not verified(SandboxResult.model_validate(data))
    data = result()
    data["execution"]["truncated"] = True
    assert not verified(SandboxResult.model_validate(data))


@pytest.mark.asyncio
async def test_failed_checks_are_persisted_without_claiming_success(tmp_path):
    async def runner(*args):
        return result([{"name": "real assertion", "passed": False}])
    jobs, _, _ = setup(tmp_path, runner)
    job = draft(jobs)
    completed = await jobs.run("admin", "session-a", job["id"], job["digest"])
    assert completed["state"] == "verification_failed"
    assert completed["result"]["execution"]["stdout"] == "created"


@pytest.mark.asyncio
async def test_pause_cancels_active_job(tmp_path):
    started, cancelled = asyncio.Event(), asyncio.Event()
    async def runner(*args):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
    jobs, authority, _ = setup(tmp_path, runner)
    job = draft(jobs)
    task = asyncio.create_task(jobs.run("admin", "session-a", job["id"], job["digest"]))
    await started.wait()
    authority.pause("admin", "session-a")
    completed = await task
    assert completed["state"] == "failed"
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_rearming_invalidates_prepared_jobs(tmp_path):
    jobs, authority, _ = setup(tmp_path, lambda *args: None)
    job = draft(jobs)
    authority.stop("admin", "session-a")
    arm(authority, mode="dynamic_sandbox", capabilities=["dynamic_scripts"])
    with pytest.raises(DynamicDenied, match="expired"):
        await jobs.run("admin", "session-a", job["id"], job["digest"])


@pytest.mark.asyncio
async def test_missing_transport_never_consumes_budget(tmp_path):
    jobs, authority, _ = setup(tmp_path)
    job = draft(jobs)
    with pytest.raises(DynamicDenied, match="not configured"):
        await jobs.run("admin", "session-a", job["id"], job["digest"])
    assert authority.current()["actions_used"] == 0


@pytest.mark.asyncio
async def test_audit_failure_prevents_remote_execution(tmp_path):
    calls = []
    async def runner(*args):
        calls.append(args)
        return result()
    jobs, _, audit = setup(tmp_path, runner)
    job = draft(jobs)
    def fail(event):
        raise RuntimeError("audit unavailable")
    audit.append = fail
    with pytest.raises(RuntimeError, match="audit unavailable"):
        await jobs.run("admin", "session-a", job["id"], job["digest"])
    assert calls == []
    assert jobs.get("admin", "session-a", job["id"])["state"] == "failed"


@pytest.mark.asyncio
async def test_host_lock_rejects_second_job(tmp_path):
    started = asyncio.Event()
    async def runner(*args):
        started.set()
        await asyncio.Event().wait()
    jobs, _, _ = setup(tmp_path, runner)
    first, second = draft(jobs), draft(jobs)
    task = asyncio.create_task(jobs.run("admin", "session-a", first["id"], first["digest"]))
    await started.wait()
    try:
        with pytest.raises(DynamicDenied, match="Concurrency"):
            await jobs.run("admin", "session-a", second["id"], second["digest"])
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def test_arming_fails_closed_if_audit_is_unavailable(tmp_path):
    _, authority, audit = setup(tmp_path)
    authority.stop("admin", "session-a")
    def fail(event):
        raise RuntimeError("audit unavailable")
    audit.append = fail
    with pytest.raises(RuntimeError):
        arm(authority, mode="dynamic_sandbox", capabilities=["dynamic_scripts"])
    assert authority.current()["mode"] == "observe"


@pytest.mark.parametrize("values", [{"script": "if ("}, {"script": "x" * 16001},
                                    {"timeout_seconds": 121}, {"timeout_seconds": True},
                                    {"network": True}])
def test_script_validation(values):
    with pytest.raises(ValidationError):
        Scripts.model_validate({"script": "print(1)", "verification": "print(2)", **values})
