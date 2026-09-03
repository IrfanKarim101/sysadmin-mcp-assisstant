# Project Phases: Read-Only Sysadmin Assistant (MCP Tool)

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
