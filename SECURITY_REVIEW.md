# Security review — 2026-09-01

## Scope

This review exercised the local application, MCP, audit, presentation, host
configuration, SSH transport, and Linux forced-command boundaries. It did not
deploy to a Linux test host, so kernel permissions, sshd behavior, sudo/group
membership, log rotation, and distribution-specific binary paths remain to be
validated live.

## Attack matrix

| Attack | Expected boundary | Result |
|---|---|---|
| Shell separators, pipes, redirects, substitutions | Forced command | Denied |
| Interactive shell, PTY, SCP, SFTP | sshd/forced command | Denied by policy tests; live test pending |
| Service restart/stop and arbitrary systemctl options | Typed policy | Denied |
| Grep pattern containing quotes and shell syntax | Argv boundary | Preserved as one data argument |
| Relative, traversing, control-character, cross-host log paths | Host policy | Denied before transport |
| Oversized line, pattern, command, parameter, and report requests | Layer-specific bounds | Denied or safely hashed/truncated |
| Prompt instructions embedded in log output | Presentation/MCP | Preserved as raw data; content-blind summary remains inert |
| SQL syntax embedded in parameters/output | SQLite bindings | Stored as data |
| Audit UPDATE/DELETE | SQLite triggers | Aborted |
| Audit writer unavailable before execution | Executor | Failed closed; transport not called |
| Missing terminal audit event after interruption | Event model | Detectable as unmatched `attempted` event |
| Unbounded SSH response | Streaming transport | Fixed: channel is terminated at the byte cap |
| Writable or symlinked forced-command policy | OS gate | Fixed: regular, root-owned, non-group/world-writable file required |
| Arbitrary MCP command/argv input | MCP schema | No such tool or parameter exists |

## Findings fixed during review

### SR-001: SSH output was bounded too late

`connection.run()` accumulated the complete remote response before the
executor truncated it. A hostile server or unexpectedly verbose command could
therefore amplify memory usage. The transport now drains stdout and stderr
concurrently in bounded chunks, terminates/closes the SSH process at 256 KiB
per stream, and propagates the truncation flag. The executor retains its
independent byte and line caps.

### SR-002: Forced-command policy ownership was assumed

Deployment documentation required a root-owned policy, but runtime did not
verify it. The gate now rejects symlinks/non-regular files, non-root ownership,
and group/world write permissions before parsing the allowlist.

## Audit completeness

Regression tests call all six executor capabilities. Every command produces a
durably ordered `attempted` and `success`/`error` pair sharing one request ID.
Policy denials produce one `denied` event and no transport call. Audit failure
before the attempted event prevents SSH execution.

## Residual risks and required live checks

- Deploy Phase 2 to the disposable Linux host and run every escape command in
  `hardening/README.md`; confirm exit status 126 and no created files.
- Confirm the restricted account has no sudo entry, administrative group,
  writable authorized-keys/policy files, forwarding, PTY, cron, or systemd
  user-service path.
- Verify every fixed binary path and ensure binaries/directories are root-owned
  and not writable by the restricted user.
- Exercise real log rotation and ensure ACLs grant only intended reads. An
  allowlisted symlink must not be writable or retargetable by the restricted
  account.
- SQLite triggers prevent accidental row mutation, but the service account can
  still delete a database file it owns. Ship immutable copies off-host or add a
  separate audit-writer service before production use.
- Rate limiting and operational rollout controls remain Phase 8 work.
- Run a dependency vulnerability scanner in CI; this local review ran tests,
  Ruff, compilation, and package consistency checks but not an online advisory
  database scan.

## Re-run criteria

Repeat this review after adding any command, changing command arguments,
altering MCP schemas, changing sshd/account configuration, or adding an
LLM-backed summary provider.
