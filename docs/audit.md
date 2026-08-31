# Phase 3: append-only audit log

`SQLiteAuditLog` records every executor action. Supplying an audit sink is
mandatory when constructing `ReadOnlyExecutor`; if the initial audit write
fails, the SSH transport is not called.

## Event lifecycle

Each approved command has a UUID request ID and two immutable events:

1. `attempted` is committed with the exact shell-escaped argv before SSH runs.
2. `success` or `error` is committed afterward with duration, a bounded output
   excerpt, and SHA-256 of the complete output.

An `attempted` event without a matching terminal event identifies an
interrupted or hung operation. Requests rejected by the typed policy produce a
single `denied` event and no command is sent to SSH.

Parameters and all other values use SQLite bound parameters. Parameter JSON is
capped at 8 KiB; oversized values are replaced by their SHA-256. Output
excerpts are capped at 4 KiB while the full-output hash remains available for
integrity comparisons.

## Append-only controls

The schema installs `BEFORE UPDATE` and `BEFORE DELETE` triggers which abort
changes to `action_log`. The database is created with mode `0600`, subject to
platform filesystem semantics. Store it in a directory writable only by the
service account, back it up off-host, and do not expose the path through MCP.

SQLite has no database users or INSERT-only grants. A separate privileged
writer process would add another boundary, but is not yet used in this
single-process service. The triggers prevent accidental mutation; filesystem
ownership and external copies protect against service-account compromise.

## Viewing recent events

The report command is local administrative tooling and caps queries at 1,000
rows:

```sh
sysadmin-audit-report /var/lib/sysadmin-mcp/audit.db --limit 50
```

Do not edit rows to resolve an incident. Append a separate operational record
outside this database so the original evidence stays unchanged.
