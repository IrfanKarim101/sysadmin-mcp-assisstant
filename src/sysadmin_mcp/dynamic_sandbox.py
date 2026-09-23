"""Host-side rootless Podman helper. Never runs generated code on the host.

Install this package and policy as root; execute this helper as a dedicated
unprivileged SSH user. The default read-only SSH gate is intentionally unchanged.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import sys
from pathlib import Path
from uuid import uuid4

from .dynamic_execution import Output, SandboxResult, Scripts
from .forced_command import validate_policy_file

POLICY = "/etc/evesdropctl-dynamic.json"
PODMAN = "/usr/bin/podman"
IMAGE = re.compile(r"^[a-z0-9][a-z0-9./:_-]{1,200}@sha256:[0-9a-f]{64}$")
MAX_OUTPUT = 32_768


def container_command(image: str, name: str, lifetime: int) -> tuple[str, ...]:
    if not IMAGE.fullmatch(image) or not re.fullmatch(r"evd-[0-9a-f]{32}", name):
        raise ValueError("A digest-pinned approved image and generated container name are required")
    if not 1 <= lifetime <= 150:
        raise ValueError("Invalid container lifetime")
    return (PODMAN, "run", "--detach", "--rm", "--pull=never", "--name", name,
            "--image-volume=ignore",
            "--network=none", "--read-only", "--read-only-tmpfs=false",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534",
            "--pids-limit=32", "--memory=256m", "--memory-swap=256m", "--cpus=1",
            "--log-driver=none", "--timeout", str(lifetime),
            "--tmpfs=/work:rw,noexec,nosuid,nodev,size=32m,mode=1777",
            "--workdir=/work", "--env=PYTHONDONTWRITEBYTECODE=1", "--env=TMPDIR=/work",
            "--entrypoint=python3", image, "-I", "-c",
            "import time; time.sleep(150)")


async def bounded_process(argv: tuple[str, ...], source: str = "", *, process_group=False, cwd=None) -> Output:
    proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
                                              stdout=asyncio.subprocess.PIPE,
                                              stderr=asyncio.subprocess.PIPE,
                                              start_new_session=process_group, cwd=cwd)

    def kill():
        try:
            if process_group:
                os.killpg(proc.pid, signal.SIGKILL)
            elif proc.returncode is None:
                proc.kill()
        except ProcessLookupError:
            pass

    async def read(stream):
        data = bytearray()
        truncated = False
        while chunk := await stream.read(4096):
            if truncated:
                continue  # Drain buffered pipe bytes after termination so wait() can finish.
            if len(data) + len(chunk) > MAX_OUTPUT:
                data.extend(chunk[:MAX_OUTPUT - len(data)])
                truncated = True
                if proc.returncode is None:
                    kill()
            else:
                data.extend(chunk)
        return data.decode("utf-8", errors="replace"), truncated

    async def write():
        try:
            proc.stdin.write(source.encode())
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.stdin.close()

    try:
        stdout, stderr, _ = await asyncio.gather(read(proc.stdout), read(proc.stderr), write())
        await proc.wait()
        return Output(exit_status=proc.returncode, stdout=stdout[0], stderr=stderr[0],
                      truncated=stdout[1] or stderr[1])
    finally:
        if process_group:
            kill()
        if proc.returncode is None:
            kill()
            await proc.communicate()


async def execute(scripts: Scripts, image: str) -> SandboxResult:
    name = "evd-" + uuid4().hex
    result = None
    try:
        async with asyncio.timeout(scripts.timeout_seconds):
            started = await bounded_process(container_command(image, name, scripts.timeout_seconds + 5))
            if started.exit_status != 0 or started.truncated:
                return SandboxResult(execution=started)
            # Separate interpreter invocations share only the ephemeral /work filesystem.
            command = (PODMAN, "exec", "--interactive", name, "python3", "-I", "-")
            execution = await bounded_process(command, scripts.script)
            verification = None
            if execution.exit_status == 0 and not execution.truncated:
                verification = await bounded_process(command, scripts.verification)
            result = SandboxResult(execution=execution, verification=verification)
    finally:
        # Also removes partially created containers after setup failure/cancellation.
        async with asyncio.timeout(10):
            cleanup = await bounded_process((PODMAN, "rm", "--force", "--ignore", name))
            if cleanup.exit_status != 0:
                raise RuntimeError("Sandbox cleanup failed; inspect host before another run")
    return result


def load_policy() -> dict:
    validate_policy_file(POLICY)
    policy = json.loads(Path(POLICY).read_text(encoding="utf-8"))
    if policy.get("enabled") is not True or policy.get("environment") not in {"development", "disposable_lab"}:
        raise ValueError("Dynamic sandbox is not enabled for this lab host")
    if os.geteuid() == 0 or policy.get("uid") != os.geteuid():
        raise ValueError("Sandbox must run as the policy-approved unprivileged user")
    if not isinstance(policy.get("image"), str) or not IMAGE.fullmatch(policy["image"]):
        raise ValueError("Approved image must be pinned by digest")
    return policy


async def host_main() -> int:
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGHUP):
        loop.add_signal_handler(sig, task.cancel)
    policy = load_policy()
    # Serialize all helper jobs for this account, including different API processes.
    import fcntl
    runtime = Path(f"/run/user/{os.geteuid()}")
    if not runtime.is_dir() or runtime.stat().st_uid != os.geteuid():
        raise ValueError("Rootless user runtime directory is unavailable")
    fd = os.open(runtime / "evesdropctl-dynamic.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        reader = asyncio.StreamReader(limit=100_001)
        protocol = asyncio.StreamReaderProtocol(reader)
        pipe, _ = await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
        raw = bytearray()
        try:
            async with asyncio.timeout(10):
                while chunk := await reader.read(4096):
                    raw.extend(chunk)
                    if len(raw) > 100_000:
                        raise ValueError("Sandbox request is too large")
        finally:
            pipe.close()
        scripts = Scripts.model_validate_json(bytes(raw))
        result = await execute(scripts, policy["image"])
        print(result.model_dump_json())
    return 0


def main() -> int:
    if len(sys.argv) != 1 or os.name != "posix":
        print("Linux sandbox helper accepts stdin only", file=sys.stderr)
        return 126
    try:
        return asyncio.run(host_main())
    except (Exception, asyncio.CancelledError) as error:  # noqa: BLE001 - CLI sanitizes all failures
        print(json.dumps({"error": type(error).__name__}), file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
