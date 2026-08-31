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

Phase 2's deployable OS hardening is available in [`hardening/`](hardening/).
It uses an OpenSSH forced-command gate with fixed absolute executables, a
root-owned log allowlist, disabled interactive/forwarding features, and an
adversarial verification checklist. Deployment and live escape testing must be
performed on the disposable Linux host before Phase 2 is considered complete.

Phase 3's mandatory append-only SQLite audit sink is implemented. It records a
durable attempt before transport execution, a terminal success/error event,
and policy denials, with bounded excerpts and full-output hashes. See
[`docs/audit.md`](docs/audit.md) for the event and operational model.

Phase 4's typed MCP stdio adapter exposes the six diagnostic capabilities with
generated bounded schemas and read-only annotations. It has no raw command or
generic SSH tool. See [`docs/mcp-server.md`](docs/mcp-server.md) for runtime and
validation instructions.

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

Run the MCP server after creating the host configuration:

```powershell
sysadmin-mcp --config config/hosts.toml --audit-db data/audit.db
```

Copy `config/hosts.example.toml` to `config/hosts.toml` only after the test
host is prepared. `config/hosts.toml`, private keys, and SQLite files are
ignored by Git.
