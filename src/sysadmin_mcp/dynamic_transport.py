"""Fixed SSH helper invocation with bounded JSON input and output."""
from __future__ import annotations

import asyncio
import os

from .dynamic_execution import SandboxResult, Scripts
from .transport import _read_bounded_stream


class DynamicSSHRunner:
    helper = "/usr/local/bin/sysadmin-dynamic-sandbox"
    def __init__(self, hosts, password_provider):
        self.hosts, self.password_provider = hosts, password_provider

    async def __call__(self, host_name: str, scripts: Scripts):
        import asyncssh

        host = self.hosts().get(host_name)
        if host is None or host.environment not in {"development", "disposable_lab"}:
            raise ValueError("Dynamic execution requires an enrolled lab host")
        if not host.known_hosts:
            raise ValueError("Pinned SSH host identity is required")
        password = self.password_provider(host) or (
            os.environ.get(host.password_env) if host.password_env else None
        )
        async with asyncssh.connect(host.hostname, port=host.port, username=host.username,
                                    known_hosts=host.known_hosts,
                                    client_keys=[str(key) for key in host.client_keys] or None,
                                    password=password, login_timeout=10, connect_timeout=10) as connection:
            process = await connection.create_process(self.helper,
                                                       encoding="utf-8", errors="replace")
            try:
                process.stdin.write(scripts.model_dump_json())
                process.stdin.write_eof()

                def stop():
                    process.terminate()
                    process.close()

                async with asyncio.timeout(scripts.timeout_seconds + 20):
                    (stdout, cut), (_stderr, error_cut) = await asyncio.gather(
                        _read_bounded_stream(process.stdout, 500_000, stop),
                        _read_bounded_stream(process.stderr, 4096, stop),
                    )
                    await process.wait_closed()
                if process.exit_status != 0 or cut or error_cut:
                    raise RuntimeError("Remote script helper failed or is not provisioned; inspect host setup")
                return SandboxResult.model_validate_json(stdout).model_dump()
            finally:
                process.terminate()
                process.close()
