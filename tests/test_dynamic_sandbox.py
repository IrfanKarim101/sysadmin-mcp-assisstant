import asyncio
import sys

import pytest

from sysadmin_mcp import dynamic_sandbox as sandbox
from sysadmin_mcp.dynamic_execution import Output, Scripts

IMAGE = "docker.io/library/python@sha256:" + "a" * 64


def test_container_command_enforces_isolation_and_pinning():
    argv = sandbox.container_command(IMAGE, "evd-" + "b" * 32, 35)
    for flag in ["--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                 "--security-opt=no-new-privileges", "--pids-limit=32", "--user=65534:65534",
                 "--memory=256m", "--cpus=1", "--log-driver=none"]:
        assert flag in argv
    assert "--privileged" not in argv and "--volume" not in argv
    with pytest.raises(ValueError):
        sandbox.container_command("python:latest", "evd-" + "b" * 32, 30)


@pytest.mark.asyncio
async def test_real_subprocess_output_is_bounded():
    output = await sandbox.bounded_process((sys.executable, "-c", "print('x' * 200000)"))
    assert output.truncated and len(output.stdout) <= sandbox.MAX_OUTPUT


@pytest.mark.asyncio
async def test_script_and_verifier_run_separately_and_container_is_removed(monkeypatch):
    calls = []
    async def process(argv, source=""):
        calls.append((argv, source))
        return Output(exit_status=0, stdout="ok", stderr="", truncated=False)
    monkeypatch.setattr(sandbox, "bounded_process", process)
    await sandbox.execute(Scripts(script="print(1)", verification="print(2)"), IMAGE)
    assert calls[1][1] == "print(1)" and calls[2][1] == "print(2)"
    assert calls[-1][0][1:4] == ("rm", "--force", "--ignore")


@pytest.mark.asyncio
async def test_timeout_still_removes_container(monkeypatch):
    calls = []
    async def process(argv, source=""):
        calls.append(argv)
        if source:
            await asyncio.Event().wait()
        return Output(exit_status=0, stdout="ok", stderr="", truncated=False)
    monkeypatch.setattr(sandbox, "bounded_process", process)
    with pytest.raises(TimeoutError):
        await sandbox.execute(Scripts(script="print(1)", verification="print(2)", timeout_seconds=1), IMAGE)
    assert calls[-1][1] == "rm"
