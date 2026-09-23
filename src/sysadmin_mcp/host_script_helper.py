"""Opt-in Linux helper: generated Python runs with the SSH account's host privileges.

This is NOT a sandbox. Root-owned policy and explicit API authority are required.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import tempfile
from pathlib import Path

from .dynamic_execution import HostScripts, SandboxResult
from .dynamic_sandbox import bounded_process
from .forced_command import validate_policy_file

POLICY = "/etc/evesdropctl-host-scripts.json"


def load_policy():
    validate_policy_file(POLICY)
    policy = json.loads(Path(POLICY).read_text())
    if (policy.get("enabled") is not True
            or policy.get("environment") not in {"development", "disposable_lab"}
            or type(policy.get("uid")) is not int
            or policy["uid"] != os.geteuid() or os.geteuid() == 0):
        raise ValueError("Host scripts are not enabled for this lab account")
    return policy


async def execute(scripts):
    # Separate interpreters: the verifier reads actual host state, not Python globals.
    with tempfile.TemporaryDirectory(prefix="evesdropctl-job-") as work:
        async with asyncio.timeout(scripts.timeout_seconds):
            command = (sys.executable, "-I", "-")
            execution = await bounded_process(command, scripts.script, process_group=True, cwd=work)
            verification = None
            if execution.exit_status == 0 and not execution.truncated:
                verification = await bounded_process(command, scripts.verification,
                                                     process_group=True, cwd=work)
            return SandboxResult(execution=execution, verification=verification)


async def host_main():
    import fcntl

    load_policy()
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    for sig in (signal.SIGTERM, signal.SIGHUP):
        loop.add_signal_handler(sig, task.cancel)
    # Admin provisions this account-owned directory, not a world-writable lock.
    runtime = Path(f"/run/evesdropctl-host-scripts/{os.geteuid()}")
    if not runtime.is_dir() or runtime.is_symlink() or runtime.stat().st_uid != os.geteuid():
        raise ValueError("Host script runtime directory is not provisioned")
    fd = os.open(runtime / "job.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        reader = asyncio.StreamReader(limit=100_001)
        pipe, _ = await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
        raw = bytearray()
        try:
            async with asyncio.timeout(10):
                while chunk := await reader.read(4096):
                    raw.extend(chunk)
                    if len(raw) > 100_000:
                        raise ValueError("Request too large")
        finally:
            pipe.close()
        result = await execute(HostScripts.model_validate_json(bytes(raw)))
        print(result.model_dump_json())
    return 0


def main():
    if os.name != "posix" or len(sys.argv) != 1:
        return 126
    try:
        return asyncio.run(host_main())
    except (Exception, asyncio.CancelledError) as error:  # noqa: BLE001 - CLI sanitizes failures
        print(json.dumps({"error": type(error).__name__}), file=sys.stderr)
        return 126
