# SysAdmin MCP Assistant

A security-first MCP service for **read-only** diagnostics on approved Linux
hosts over SSH. The complete design and delivery plan are in
[`project_context.md`](project_context.md) and
[`project-phases.md`](project-phases.md).

## Current status

Phase 1's executor policy is implemented. `ReadOnlyCommandPolicy` builds a
small, fixed set of argument vectors for ports, services, resource snapshots,
allowlisted log reads/searches, and active users. `ReadOnlyExecutor` applies
uniform output bounds, while the AsyncSSH implementation remains isolated in
the transport module. MCP tools are not implemented yet.

Host log access is configured with exact absolute paths in
`config/hosts.toml`; globs, relative paths, and paths containing traversal are
not accepted. Log line requests are capped at 500 lines, and every command
result is capped at 2,000 lines and 256 KiB per output stream, with
`CommandResult.truncated` indicating when a cap was applied.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```

Copy `config/hosts.example.toml` to `config/hosts.toml` only after the test
host is prepared. `config/hosts.toml`, private keys, and SQLite files are
ignored by Git.
