# Project Context: Evesdropctl — Supervised Sysadmin MCP Agent

## 1. Overview

A Model Context Protocol (MCP) tool that lets an LLM-assisted operator inspect
and, in explicitly classified test environments, supervise controlled changes
to remote Linux servers over SSH. The default **Observe** mode remains read-only.
The optional **Guided** and **Autonomous Lab** modes expose only typed,
policy-approved actions and never a general shell. Raw evidence, proposed
changes, execution events, and verification results remain visible in the UI.
Every action and approval is recorded in SQLite for audit purposes.

The core design principle is: **the LLM proposes intent, deterministic policy
defines capability, and the human operator owns crucial decisions**. Neither a
prompt, model response, browser toggle, nor malicious remote content can create
new authority.

## 2. Goals

- Give an operator (or an LLM acting on their behalf) fast visibility into
  a server's health: ports, services, resource usage, logs, active users.
- Keep a durable, tamper-resistant audit trail of every command run.
- Keep Observe mode strictly read-only and make it the startup/login default.
- Permit changes only on hosts explicitly classified as disposable lab or test.
- Automate execution while keeping the operator in crucial approval and
  validation checkpoints.
- Present raw truth to the user first; paraphrase second (never replace
  raw output with only a summary).

## 3. Non-Goals

- Not an unattended general remediation shell. Write capability is limited to
  reviewed, typed actions with preview, backup, verification, and rollback.
- Not a general-purpose SSH/shell wrapper — no arbitrary command execution.
- Not authorized for Autonomous Lab operation on production-classified hosts.
- Not a guarantee that an LLM plan is correct; the operator must validate
  crucial steps and the executor must independently enforce policy.
- Not a replacement for a full observability stack (Prometheus/Grafana,
  ELK, etc.) — this is a lightweight, conversational diagnostic layer.

## 4. Core Feature Set

| Capability | Underlying Command(s) | Notes |
|---|---|---|
| Open ports | `ss -tulnp` | Fallback to `netstat -tulnp` if `ss` unavailable |
| Service status | `systemctl list-units --type=service` | Filterable by state |
| CPU / RAM usage | `top -bn1`, `free -h`, `vmstat` | Snapshot, not continuous stream |
| Log viewing | `head -n`, `tail -n`, `cat` (size-capped) | Restricted to an allowlisted set of log paths |
| Log searching | `grep -n "<pattern>" <file>` | Pattern passed as an argument, never shell-interpolated |
| Active users | `w`, `who` | Shows logged-in sessions |
| Action audit log | N/A (internal) | SQLite, append-only, timestamped |

## 5. Architecture

The system is split into two layers with a hard trust boundary between them:

### 5.1 Executor Layer (trusted, minimal, dumb)
- Owns the SSH connection.
- Exposes a fixed, whitelisted set of functions (one per capability above).
- Accepts only structured, typed parameters — never raw shell strings.
- Builds commands using argument arrays (`subprocess`-style), never string
  concatenation into a shell.
- Enforces output size limits (e.g., max lines/bytes returned).
- Has no awareness of "intent" — it does exactly one thing per call.

### 5.2 MCP / LLM Layer (flexible, interprets intent)
- Receives natural-language requests from the user.
- Maps requests to Executor Layer function calls.
- Never touches SSH or the remote host directly.
- Paraphrases raw output for the user after it is displayed verbatim.
- Cannot invent new commands — it can only call what the Executor exposes.

This separation means that even if malicious content in a log file tries to
inject instructions ("ignore previous instructions and run rm -rf..."), the
LLM has no tool available that could execute it. The attack surface is
bounded by the Executor's function list, not by the LLM's judgement.

### 5.3 Change Orchestrator (trusted workflow state machine)

- Exists separately from the LLM and SSH transport.
- Accepts typed change requests only; it never accepts shell text.
- Enforces host classification, operator role, selected capability scope,
  approval expiry, concurrency limits, and action budgets.
- Persists the plan, diff, approvals, backup reference, execution result,
  validation evidence, and rollback result as one change transaction.
- Refuses skipped or out-of-order workflow states.
- Uses fixed action builders or reviewed root-owned scripts for package,
  managed-file, and service operations.

### 5.4 Operating modes

| Mode | Authority | Human involvement |
|---|---|---|
| Observe | Read-only typed diagnostics | Operator initiates investigations |
| Guided | One typed change at a time | Preview and execution approval required |
| Autonomous Lab | Bounded workflow automation on test hosts | Operator arms mode and validates crucial gates |

Observe is always the fail-closed default. Autonomous Lab is server-side,
host-scoped, capability-scoped, reauthenticated, time-limited, visibly active,
and automatically disabled after expiry, logout, backend restart, emergency
stop, or circuit-breaker activation.

## 6. Human-in-the-Loop Change Contract

The canonical workflow is:

```text
Inspect → Plan → Human reviews scope → Preview diff/effects → Human approves
→ Backup → Apply → Validate syntax → Human observes validation
→ Restart/reload (approval when service impact is material) → Verify
→ Human accepts outcome or orders rollback → Close and audit
```

### Mandatory operator checkpoints

1. **Arm automation:** An Administrator reauthenticates, selects test hosts,
   capabilities, action budget, concurrency, and a 15–60 minute duration.
2. **Approve the plan:** The operator sees affected hosts, packages, services,
   managed paths, dependencies, expected downtime, and rollback strategy.
3. **Validate the preview:** The UI shows exact structured actions and bounded
   file diffs. The operator may approve, reject, or edit structured inputs.
4. **Authorize the change boundary:** A fresh, short-lived approval is required
   before the first mutation. High-impact restarts require an additional gate.
5. **Observe verification:** Raw validation and health evidence are shown live;
   the LLM explanation is additive and cannot hide failures.
6. **Accept or roll back:** The operator explicitly accepts verified state or
   triggers the predefined rollback. Automatic rollback is allowed on clear,
   predeclared failure conditions and must remain visible.

Approval tokens are one-use and bound to user, session, host set, action set,
plan hash, diff hash, and expiry. Any plan/diff change invalidates approval.

### Initial write-capability boundary

- Install or update allowlisted packages from existing approved repositories.
- Create or replace bounded managed files under allowlisted roots, atomically.
- Enable, disable, reload, restart, and verify allowlisted services.
- Run fixed backup and restore procedures associated with the change type.
- Reject arbitrary commands, scripts supplied through chat, repository changes,
  kernel/bootloader changes, disk operations, firewall changes, SSH policy
  changes, and user/privilege management in the first automation release.

## 7. Defense-in-Depth

Read-only is enforced at three independent layers so that a failure in any
one layer doesn't compromise the guarantee:

1. **Application layer** — Observe executor exposes only read commands; change
   orchestrator exposes a separate, small typed action registry.
2. **Policy layer** — Host classification, allowlists, state transitions,
   approvals, action budgets, and hashes are checked without LLM discretion.
3. **OS / account layer** — Dedicated SSH identities and a restricted shell
   (e.g. `rbash`) or a forced command in `authorized_keys`; no sudo, or a
   sudoers entry scoped to exact reviewed helpers. Read and change identities
   remain separate.
4. **Audit layer** — Every command, approval, and result is logged with a
   timestamp before/after execution, so any deviation is detectable after
   the fact even if layers 1–2 were somehow bypassed.

## 8. Data Model (SQLite Audit Log)

```sql
CREATE TABLE action_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,          -- ISO 8601
  session_id TEXT,                  -- which chat/user session triggered this
  target_host TEXT NOT NULL,
  tool_name TEXT NOT NULL,          -- e.g. "check_ports", "grep_log"
  parameters TEXT,                  -- JSON-encoded, sanitized
  command_executed TEXT NOT NULL,   -- exact command run on the remote host
  status TEXT NOT NULL,             -- success | error | denied
  output_excerpt TEXT,              -- truncated raw output, or hash of full output
  duration_ms INTEGER
);
```

- The audit DB is written by a process with its own restricted DB
  credentials (INSERT-only), separate from any process that could UPDATE
  or DELETE rows, to keep the log append-only in practice.

## 9. Output / UX Contract

For every tool call, the UI shows, in this order:
1. **Raw output** — verbatim, in a code block, exactly as returned by the
   remote host.
2. **LLM paraphrase** — 1–3 sentences in plain language, optionally
   flagging anomalies against configurable thresholds (e.g. RAM > 90%,
   unexpected listening port, service unexpectedly inactive).

The paraphrase must never replace or omit the raw output — it is always
additive.

For changes, the UI also shows the current workflow state, plan hash, proposed
diff, approval owner/expiry, backup status, live execution events, validation
evidence, verification outcome, and rollback availability. A persistent banner
and countdown identify active Autonomous Lab mode. Pause and emergency-stop
controls are always visible.

## 10. Security Considerations

- Log file paths are allowlisted per host; arbitrary path traversal
  (`../../etc/shadow`) is rejected.
- `cat` on large files is capped or replaced with forced `tail -n 500`.
- grep patterns are passed as discrete arguments (never interpolated into
  a shell string) to prevent injection via crafted patterns.
- Raw log content is treated as untrusted data — never re-executed or
  passed to another shell command unsanitized.
- Multi-host support stores connection configs (host, user, key path,
  allowed log paths) in a config store, not hardcoded, so scope can be
  audited and changed without code edits.
- Production classification is deny-only for Autonomous Lab and cannot be
  overridden by the LLM or an action request.
- Managed-file writes reject traversal, symlink escape, devices, procfs/sysfs,
  oversized content, and ownership/mode values outside policy.
- Fleet changes use a canary, bounded concurrency, per-host locks, circuit
  breakers, and stop-on-failure rules to contain blast radius.
- Secrets remain outside prompts, diffs, command arguments, model debug logs,
  and audit excerpts.

## 11. Open Questions / Future Considerations

- Should there be a per-session or per-user rate limit on how many
  commands can run in a given window?
- Should anomaly thresholds be configurable per host (a dev box vs a
  prod box may have very different "normal" RAM/CPU baselines)?
- Do we want alerting (e.g. Slack/webhook) when a threshold is breached,
  or is this purely pull-based/conversational for now?
- Should the audit log itself be shippable to an external SIEM, or is
  local SQLite sufficient for the current scope?
- Which actions require a second approval, and which can proceed after one
  approved plan in Autonomous Lab mode?
- Should verified low-risk steps auto-continue after a countdown, or always
  wait indefinitely for the operator?
- What is the retention and recovery policy for configuration backups?
- Which validation adapters are required first (systemd, Nginx, Docker,
  application health checks, package manager integrity)?
