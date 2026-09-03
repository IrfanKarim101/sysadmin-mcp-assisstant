# Two-day MVP runbook

Target: a working demonstration on a disposable, non-critical Linux host by
**September 3, 2026**. Do not point this build at production until every live
security check passes.

## MVP acceptance criteria

- One disposable Linux host is configured with the dedicated
  `sysadmin-readonly` account and key authentication.
- The Phase 2 forced-command and sshd restrictions are deployed.
- All approved tools return raw output followed by the safe summary.
- Non-allowlisted paths, shell escapes, service mutations, forwarding, SCP,
  SFTP, and interactive sessions fail.
- Every executed command has matching attempted and terminal audit events.
- Rate-limit errors are clear and do not reach SSH.
- `sysadmin-preflight` and the full local test suite pass.

## Day 1 — local release and host preparation

1. Create a release branch/tag or record the exact commit SHA. Install and
   test the project:

   ```sh
   python -m pip install -e ".[dev]"
   pytest
   ruff check src tests
   ```

2. Prepare local state and add the disposable host:

   ```sh
   mkdir -p data
   cp config/hosts.example.toml config/hosts.toml
   sysadmin-hosts --config config/hosts.toml list
   sysadmin-preflight --config config/hosts.toml --audit-db data/audit.db
   ```

3. On the test host, follow `hardening/README.md` to install the wheel, create
   the restricted account, deploy the root-owned policy, add the restricted
   public key, and install the sshd Match block.

4. Before reloading sshd, keep an existing administrator session open and run
   `sshd -t`. Verify the forced-command policy and fixed binaries are owned by
   root and not writable by the restricted account.

## Day 2 — adversarial validation and demo

1. Run every approved SSH command and every denial in
   `hardening/README.md`. Confirm denied calls return 126 and no marker file is
   created.

2. Run the MCP server with conservative MVP limits:

   ```sh
   sysadmin-mcp \
     --config config/hosts.toml \
     --audit-db data/audit.db \
     --ssh-timeout 15 \
     --rate-limit 30 \
     --rate-window 60
   ```

3. Connect the local MCP client and try ports, failed services, resources,
   allowlisted log tail/search, and active users. Then try `/etc/shadow`, 501
   lines, an injection-shaped grep pattern, and repeated calls beyond the rate
   limit.

4. Inspect the audit trail:

   ```sh
   sysadmin-audit-report data/audit.db --limit 100
   ```

   Match every SSH command to an `attempted` plus `success`/`error` pair and
   verify denied executor requests have `denied` events.

5. Capture the commit SHA, host OS/OpenSSH versions, command results, audit
   sample, and unresolved issues. The demo is accepted only if all acceptance
   criteria above pass.

## Rollback

If any escape or unexpected write succeeds, stop the MCP server immediately,
lock the restricted account, remove or disable the sshd Match block, validate
and reload sshd, preserve the audit database and server logs, and return to the
disposable-host snapshot. Do not weaken the policy merely to make a demo pass.

## Explicitly outside the two-day MVP

- Production or critical-host rollout.
- Automated remediation or any write operation.
- Hosted/network MCP transport and multi-user authentication.
- External SIEM shipping and a separate audit-writer service.
- LLM-backed summaries and sophisticated resource anomaly parsing.
