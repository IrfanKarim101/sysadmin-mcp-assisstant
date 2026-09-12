# Project Phases: Evesdropctl Sysadmin MCP Agent

Each phase produces something runnable/testable on its own before moving
to the next. Security-hardening steps are woven in early rather than
bolted on at the end.

---

## Phase 0 — Foundations & Environment Setup

**Goal:** Have a safe sandbox to build against before writing any real logic.

- [ ] Stand up a throwaway test VM (or container with sshd) to develop against
      — never develop directly against production.
- [ ] Create a dedicated, restricted SSH user on the test host
      (`sysadmin-readonly` or similar).
- [ ] Set up SSH key-based auth (no passwords).
- [x] Decide on stack: Python (`asyncssh`/`paramiko` + `sqlite3`) or
      Node (`ssh2` + `better-sqlite3`). Python is recommended for MCP
      server ecosystem maturity.
- [x] Scaffold the MCP server project structure (Executor module,
      MCP/tool-definition module, DB module kept separate).

**Exit criteria:** Can SSH into the test box from your dev machine using
the dedicated key, manually, and confirm the restricted user can read
logs but cannot write/delete anything.

---

## Phase 1 — Executor Layer (the trust boundary)

**Goal:** Build the dumb, minimal, whitelisted command layer. No LLM
involved yet — this should be testable with plain function calls / unit
tests.

- [~] Implement SSH connection handling (connect, reuse/pool, timeout,
      disconnect).
- [~] Implement each capability as a typed function, not a raw string
      executor:
  - `check_ports(host)`
  - `check_services(host, state_filter=None)`
  - `check_resources(host)` → CPU + RAM combined
  - `read_log(host, logfile, mode, lines)` where `mode` ∈ {head, tail, cat}
  - `grep_log(host, logfile, pattern, max_lines)`
  - `who_is_on(host)`
- [~] Enforce allowlists:
  - Allowlisted log file paths per host (config-driven).
  - Reject `cat` beyond a size cap; force max line counts.
  - Reject any parameter containing shell metacharacters where not
    expected.
- [x] Build commands as argument arrays, not interpolated shell strings.
- [~] Unit tests: valid inputs succeed; malicious/out-of-scope inputs
      (path traversal, injection attempts, oversized requests) are
      rejected with clear errors.

**Exit criteria:** You can call each Executor function directly (via a
test script) against the test VM and get correct, bounded output. Attempts
to break out of scope fail safely.

---

## Phase 2 — OS-Level Read-Only Hardening

**Goal:** Make "read-only" true even if the Executor layer has a bug.

- [~] Restrict the SSH user's shell (`rbash`) or use a forced command in
      `authorized_keys` that only permits the specific whitelisted binaries.
- [~] Ensure the user has no sudo, or a sudoers entry scoped to explicit
      read-only binaries only (e.g. `/usr/bin/ss`, `/usr/bin/tail`) with
      `NOPASSWD` disabled unless required.
- [~] Verify via manual pentest-style checks: try to write a file, try to
      escape the restricted shell, try command chaining (`;`, `&&`, `|` to
      a write command) — all should fail.
- [x] Document the hardening steps so they're repeatable for any new host
      added later.

**Exit criteria:** Even with direct terminal access as the restricted
user (no app in front of it), no write/modify/delete action is possible.

---

## Phase 3 — Audit Logging (SQLite)

**Goal:** Every action is durably logged before the result is returned.

- [x] Create the `action_log` schema (see project-context.md §7).
- [x] Log entry written at call time (status=pending/attempted) and
      updated/finalized at completion (status=success/error), or logged
      as a single atomic insert after execution — decide based on whether
      you need to detect hung/interrupted calls.
- [~] Use a separate DB-writing process/connection with INSERT-only
      privileges where practical, to keep the log append-only.
- [x] Add a simple query/report script to view recent actions
      (for your own debugging, not the end-user UI yet).

**Exit criteria:** Every Executor call from Phase 1, when run, produces a
corresponding timestamped row with host, tool name, parameters, and
command executed.

---

## Phase 4 — MCP Tool Definitions & LLM Integration

**Goal:** Expose the Executor functions as MCP tools the assistant can call.

- [x] Write MCP tool schemas (name, description, structured parameters)
      for each capability — descriptions should make clear these are
      read-only and what constraints apply (e.g. "only reads logs from
      the allowlisted path set").
- [x] Wire each MCP tool to its corresponding Executor function — no
      logic beyond translation/validation should live here.
- [x] Confirm the LLM cannot pass through raw shell strings; only the
      structured parameters defined in the schema are accepted.
- [~] Test with real conversational prompts ("check what's listening on
      this box", "search the nginx error log for 502s", "who's logged in
      right now") and confirm correct tool routing.

**Exit criteria:** A user can ask natural-language questions and get
correct tool calls routed to the Executor, with results returned.

---

## Phase 5 — UI: Raw Output + Paraphrase

**Goal:** Implement the display contract — raw first, paraphrase second.

- [x] Render raw command output verbatim (code block / fixed-width).
- [~] Generate a short LLM paraphrase (1–3 sentences) underneath,
      summarizing what the output means in plain language.
- [~] (Optional, recommended) Add basic anomaly flagging in the
      paraphrase step — e.g. RAM > 90%, an inactive service that should
      be active, an unexpected listening port — based on configurable
      thresholds.
- [x] Confirm the paraphrase never replaces or hides any raw output.

**Exit criteria:** Every tool response in the UI shows both raw output
and a paraphrase, and thresholds (if implemented) correctly flag
out-of-range values.

---

## Phase 6 — Multi-Host & Config Management

**Goal:** Support more than one server without code changes.

- [x] Move host configs (hostname, SSH user, key path, allowlisted log
      paths, resource thresholds) into a config file or table.
- [x] Add a simple mechanism to add/remove hosts.
- [x] Confirm per-host allowlists are respected (a log path allowed on
      host A but not host B is correctly rejected on host B).

**Exit criteria:** Can add a second test host purely via config and
immediately query it through the same MCP tools.

---

## Phase 7 — Security Review & Adversarial Testing

**Goal:** Actively try to break your own read-only guarantee before
trusting it in a real environment.

- [x] Attempt prompt injection via crafted log content (e.g. a log line
      containing fake "instructions") and confirm the LLM has no tool
      available to act on it destructively.
- [x] Attempt path traversal, command injection, and oversized-output
      attacks against the Executor directly (bypassing the LLM).
- [x] Review the audit log for completeness — can any action occur
      without a corresponding log entry?
- [~] Review SSH user permissions one more time end-to-end (Phase 2
      checklist) after all other phases are complete, since new code
      paths may have been added.

**Exit criteria:** A written note of what was tried, what failed safely,
and any fixes made as a result.

---

## Phase 8 — Polish & Rollout

**Goal:** Make it usable day-to-day, then move beyond the test VM.

- [x] Add rate limiting per session/user if needed.
- [x] Add clear error messages for denied/out-of-scope requests (so the
      user understands *why*, not just that it failed).
- [x] Documentation: how to add a host, how to adjust thresholds, how to
      query the audit log.
- [~] Only after Phases 0–7 are solid: point at a real (non-critical)
      server, then gradually expand scope.

**Exit criteria:** Tool is usable against a real server with confidence
in the read-only guarantee and a complete audit trail.

---

## Phase 9 — Fleet Diagnostics Expansion

**Goal:** Add high-value visibility without adding a generic execution path.

- [~] Add fixed typed tools for disk/inodes, top processes, interfaces/routes,
      and Docker container status/resource snapshots.
- [ ] Add certificate-expiry checks limited to config-allowlisted endpoints.
- [ ] Add OS/kernel/uptime, reboot history, NTP, firewall, package-update,
      timer/cron, hardware, RAID, user/group, and approved file-metadata tools.
- [ ] Mirror every application command in the OS forced-command gate.
- [ ] Add injection-shaped and oversized-input tests for every parameterized tool.

**Exit criteria:** Each capability is a fixed argv builder, independently testable
without SSH, bounded, audited, and accepted by the host-side forced-command policy.

Implemented core expansion: disk/inodes, top processes, network, Docker, OS/kernel,
uptime/boots, NTP, timers, hardware, block devices/RAID, firewall, simulated package
updates, and user/group inventory now use fixed bounded commands mirrored by the
host gate. Certificate endpoints and approved file metadata remain outstanding.

---

## Phase 10 — Fleet Overview & Historical Health

**Goal:** Make 10–30 approved VMs understandable from one operator surface.

- [ ] Fleet dashboard with status, tags, search, filters, and host detail pages.
- [ ] Bounded parallel health checks with per-host timeouts, concurrency limits,
      circuit breakers, and stale/offline detection.
- [ ] Store scheduled snapshots and show CPU, memory, disk, load, and service trends.
- [ ] Compare current state with configurable thresholds and the last healthy baseline.
- [ ] Notifications through explicitly configured channels using bounded summaries only.

**Exit criteria:** A fleet-wide check cannot exhaust the API or SSH layer, and one
unhealthy/unreachable VM cannot block results for the rest of the fleet.

Implemented core fleet engine: bounded concurrency/timeouts, per-host failure
isolation, circuit opening, serialized collection runs, five-minute scheduled
snapshots, durable indexed history, status filtering, and host history pages.
Tags, baselines, and outbound notification channels remain outstanding.

---

## Phase 11 — Read-Only Investigation Playbooks

**Goal:** Provide reviewable decision trees for common incidents.

- [ ] Fixed playbooks for high CPU/memory/load, disk pressure, service outage,
      SSH failure, connectivity issues, certificate expiry, unhealthy containers,
      and unexpected reboots.
- [ ] The LLM may select and explain a playbook but cannot create commands or steps.
- [ ] Show the executed evidence timeline and distinguish facts from interpretation.

**Exit criteria:** Every playbook step maps to an approved typed tool and is covered
by deterministic routing and termination tests.

Implemented playbooks cover CPU, memory, load, disk, service outage, SSH/network,
Docker, unexpected reboot, and security review. Every evidence entry is explicitly
marked as fact and interpretation is returned separately. Certificate-expiry
playbooks remain blocked on the Phase 9 certificate capability.

---

## Phase 12 — Security Posture Diagnostics

**Goal:** Detect risk while remaining observational.

- [ ] Failed-login/brute-force summaries, unexpected ports, privileged services,
      interactive-shell accounts, recent accounts, SSH posture, firewall exposure,
      security updates, certificate expiry, world-writable approved roots, and drift.
- [ ] Restrict filesystem checks to configured roots and predefined indicators.
- [ ] Store versioned baselines and explain every finding with raw evidence.

**Exit criteria:** Scans cannot traverse arbitrary paths, alter the host, or turn
untrusted log/file content into instructions.

---

## Phase 13 — Operator UX & Identity Hardening

**Goal:** Make the product safe for multiple daily operators.

- [ ] Host detail pages, saved templates, pinned hosts, evidence expansion, report
      export, conversation management, and session-expiry warnings.
- [ ] Named users with Administrator/Operator/Viewer roles, login throttling,
      lockout, TOTP MFA, recovery codes, session management, and auth audit events.
- [ ] Prefer OIDC for production; require HTTPS for any non-local deployment and
      encrypt sensitive configuration at rest.

**Exit criteria:** Authorization is enforced server-side for every route/tool and
the bootstrap credential is disabled after initial setup.

---

## Phase 14 — Approval-Gated Remediation (Post-MVP)

**Goal:** Add narrowly defined maintenance actions without arbitrary shell access.

- [ ] Consider only explicit actions such as restarting an allowlisted service,
      rotating an approved log, clearing a specific cache, renewing a configured
      certificate, rebooting, or applying approved security updates.
- [ ] Require effect preview, explicit confirmation, reauthentication/MFA,
      role authorization, host/action-bound short-lived approval tokens, fixed
      privileged implementations, full audit, and post-action verification.
- [ ] Never accept command text from the user or LLM.

**Exit criteria:** Independent security review confirms that approvals cannot be
replayed or widened and the privileged layer exposes no generic executor.

### Implemented first slice

- [x] Restart only an exact, per-host allowlisted service; no generic action or
      command-string API is exposed to the UI or LLM.
- [x] Require Administrator role, password reauthentication, effect preview,
      explicit confirmation, and a two-minute one-use approval tied to the
      authenticated session, host, service, and action.
- [x] Append attempted and terminal action events to the immutable audit log,
      then run a fixed post-action service-state verification.
- [x] Mirror the exact preview/restart argument shapes in the host-side gate;
      deployments still need an independently reviewed least-privilege OS
      authorization for the configured service before live use.
- [x] Run a named database-backup job mapped by a root-owned host policy to one
      exact executable beneath `/root`; reject paths, arguments, shell syntax,
      unknown IDs, replay, and cross-session approval use.

---

## Phase 15 — Automation Modes & Lab Classification

**Goal:** Introduce authority modes without introducing write commands yet.

- [x] Add server-side `observe`, `guided`, and `autonomous_lab` modes; never
      trust a browser-only toggle.
- [x] Classify every host as production, staging, development, or disposable
      lab, with Autonomous Lab denied for production.
- [x] Require Administrator reauthentication to arm automation and bind it to
      selected hosts, capabilities, action budget, concurrency, and expiry.
- [x] Add a persistent mode banner, countdown, pause, and emergency stop.
- [x] Reset to Observe on expiry, logout, backend restart, policy change,
      repeated failure, or emergency stop.
- [x] Audit mode requests, approvals, denials, activation, expiry, and stop.

**Human checkpoint:** The operator must explicitly select the test hosts and
capability scope and confirm the time-limited automation session.

**Exit criteria:** UI tampering, stale tokens, role changes, or production hosts
cannot enable write authority; no actual mutation capability exists yet.

---

## Phase 16 — Change Transactions, Plans & Approval Gates

**Goal:** Build the deterministic workflow state machine before adding writers.

- [ ] Add change transactions with states for inspected, planned, previewed,
      approved, backed-up, applying, validating, verifying, accepted,
      rollback-required, rolled-back, failed, and cancelled.
- [ ] Define typed plans containing exact hosts, action IDs, structured inputs,
      expected effects, service impact, validation steps, and rollback strategy.
- [ ] Hash the plan and preview; bind one-use approvals to user, session, host
      set, hashes, and expiry. Any edit invalidates approval.
- [ ] Reject skipped, repeated, expired, or out-of-order state transitions.
- [ ] Stream every transition and decision to the UI and immutable audit trail.

**Human checkpoints:** The operator reviews scope and risk, edits or rejects the
structured plan, validates the final preview, then authorizes the mutation
boundary with a fresh approval.

**Exit criteria:** A simulated change can traverse the entire workflow, including
denial and rollback paths, without executing a remote write.

---

## Phase 17 — Backup, Restore & Rollback Foundation

**Goal:** Make recovery a prerequisite rather than an afterthought.

- [ ] Define typed backup adapters for managed files, package state, and service
      state using reviewed host-side helpers.
- [ ] Store backup references, hashes, ownership/mode metadata, and expiry;
      never place secret material in prompts or audit excerpts.
- [ ] Implement idempotent predefined rollback actions and post-rollback checks.
- [ ] Refuse Apply when a required backup is missing, unverifiable, or stale.
- [ ] Add retention, cleanup, disk-space limits, and recovery testing.

**Human checkpoint:** Before Apply, the operator sees and validates backup status
and the exact rollback plan. After failure, the operator observes automatic
rollback or explicitly chooses rollback when the failure is ambiguous.

**Exit criteria:** Simulated and test-host failures restore the captured prior
state and produce complete verification evidence.

---

## Phase 18 — Managed File Automation

**Goal:** Safely create or replace configuration files on lab hosts.

- [ ] Allow writes only beneath policy-defined roots and named path IDs.
- [ ] Reject traversal, symlink escape, devices, procfs/sysfs, oversized content,
      unsupported encoding, and ownership/modes outside policy.
- [ ] Produce a bounded unified diff and capture the original before approval.
- [ ] Write to a temporary file, set approved metadata, validate, then atomically
      rename; never stream model text directly into a shell.
- [ ] Add configuration-specific validators beginning with Nginx and systemd.

**Human checkpoints:** The operator reviews the full bounded diff and affected
path before approval, then observes syntax validation before service activation.

**Exit criteria:** Valid changes apply atomically; malicious paths and content
shapes fail before transport; validation failure restores the original file.

---

## Phase 19 — Package Lifecycle Automation

**Goal:** Install or update allowlisted packages without arbitrary package-manager use.

- [ ] Add typed package name/version inputs and per-host allowlists.
- [ ] Use existing approved repositories only; deny repository/key addition.
- [ ] Preview versions, dependencies, removals, download size, disk impact, locks,
      held packages, and reboot requirements.
- [ ] Add package-manager-specific fixed builders for supported distributions.
- [ ] Verify installed version and dependent service health after the change.
- [ ] Stop fleet rollout after a failed canary or dependency/removal surprise.

**Human checkpoints:** The operator approves the dependency/removal preview and
observes canary verification before allowing remaining test hosts to continue.

**Exit criteria:** Only allowlisted packages and versions can change, and the
transaction records before/after state plus rollback limitations.

---

## Phase 20 — Service Configuration & Lifecycle

**Goal:** Connect managed configuration to controlled service activation.

- [ ] Extend the typed service registry for enable, disable, reload, restart,
      status verification, and service-specific health checks.
- [ ] Require successful syntax/configuration validation before reload/restart.
- [ ] Distinguish reload from restart and surface expected downtime.
- [ ] Verify process state, listening ports, recent bounded logs, and configured
      application health checks after activation.
- [ ] Automatically invoke the predefined rollback on clear failure conditions.

**Human checkpoints:** The operator observes validation evidence. Material-impact
restarts require an additional approval immediately before execution; the
operator then accepts verified state or orders rollback.

**Exit criteria:** A service cannot be activated with invalid configuration, and
command success alone is never treated as verified health.

---

## Phase 21 — Supervised Automation UI & Fleet Controls

**Goal:** Make long-running automation understandable and interruptible.

- [ ] Build a change workspace showing Inspect, Plan, Preview, Backup, Apply,
      Validate, Activate, Verify, and Rollback as live states.
- [ ] Show raw evidence, structured actions, diffs, approval owner/expiry,
      progress, per-host state, and rollback availability.
- [ ] Add approve, reject, edit plan, pause, resume, skip-unstarted-host,
      rollback, and emergency-stop controls with role checks.
- [ ] Use canary-first fleet rollout, bounded concurrency, per-host locks,
      action budgets, timeouts, and circuit breakers.
- [ ] Never hide failure evidence behind an LLM summary or a completed indicator.

**Human checkpoints:** The operator remains present at every crucial gate and can
halt the workflow at any time. Low-risk steps may auto-continue only when they
were included in the exact approved plan.

**Exit criteria:** An operator can watch, validate, pause, approve, and roll back
a multi-step lab change without losing the raw state of any host.

---

## Phase 22 — Adversarial Validation & Lab Release

**Goal:** Prove the supervised automation boundary before broader testing.

- [ ] Test prompt injection in logs, files, package metadata, model responses,
      and validation output.
- [ ] Test path/symlink races, command injection shapes, oversized plans/diffs,
      approval replay, cross-user/session/host use, stale-plan approval, and
      state-machine bypass.
- [ ] Test disconnects and process crashes during backup, apply, validation,
      restart, verification, and rollback.
- [ ] Verify production classification is fail-closed at UI, API, policy,
      transport identity, and host-side helper layers.
- [ ] Conduct recovery drills and document residual risks and non-rollbackable
      package operations.

**Human checkpoint:** A named operator signs off on the evidence for each failure
scenario and explicitly authorizes release to disposable lab hosts.

**Exit criteria:** Written security and recovery reports demonstrate that the LLM
cannot create authority, crucial steps cannot bypass human validation, and all
mutations remain typed, bounded, audited, recoverable, and limited to test hosts.
