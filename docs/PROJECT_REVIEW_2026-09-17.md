# Evesdropctl progress and validation report

Review date: 17 September 2026. Environment: Windows, Python 3.12, installed local Python and UI dependencies.

## Assessment

The project is a substantial local diagnostics and supervised-workflow prototype, with strong automated coverage of typed commands, approval boundaries, audit behavior, and simulated recovery. It is not yet validated for production or unattended live administration. The production UI bundle builds, but frontend type checking and both lint checks fail.

The roadmap identifies Phase 22 (adversarial validation and lab release) as active and Phase 23 (autonomous lab operations) as partial. Phases 15–21 are largely complete **within their simulated scope**. File replacement, package installation, service lifecycle workflows, and recovery records do not establish working remote mutation or restoration. The existing restart and database-backup services are separate typed live-capable paths whose remote behavior was not exercised here.

At inspection start, HEAD was `e630c62`, with existing changes to authority, web, tests, UI, roadmap, and new recipe files. During review, HEAD changed externally to `f20d34b` (scoped autonomous lab recipes and Nginx planner). This review did not commit or modify application code. Results describe the working-tree files tested, rather than a guaranteed immutable checkout.

## Executed checks

| Check | Result | Meaning |
| --- | --- | --- |
| Full Python suite | **285 passed**, 48.59 seconds | All 31 test modules passed; no reported failures or skips |
| Additional isolated API smoke checks | **103/103 passed** | 53 unauthenticated route/method checks, 17 authenticated empty-fleet GET checks, 33 missing-CSRF checks |
| UI production build (`npm run build`) | **Passed** | All five build stages completed; 13 routes listed |
| UI type check (`npx tsc --noEmit`) | **Failed: 26 diagnostics** | Account button composition and Changes preview typing |
| UI lint (`npm run lint`) | **Failed** | Type errors, accessibility, React compiler, deprecation, and other correctness findings |
| Python lint (`python -m ruff check src tests --output-format concise`) | **Failed: 15 findings** | Imports, unused symbols, and one collapsible conditional |
| Dependency consistency (`python -m pip check`) | **Passed** | Installed Python requirements are mutually consistent; not a vulnerability audit |
| Actual local configuration preflight | **Passed outside sandbox** | Configuration, SSH file existence, and audit directory checks only; no SSH connection |
| Workflow progress reproduction | **Defect reproduced** | Failed validation marks Validate and Activate complete |

The initial sandbox preflight raised PermissionError accessing the configured known-hosts file; the authorized read-only retry passed. This is not evidence of broken SSH configuration. It does show that preflight does not handle inaccessible files gracefully.

## Functionality-by-functionality matrix

All counts below are actual passing pytest cases, including parameterized cases. A passing local test is not equivalent to a live integration test.

| Feature | Cases | Verified behavior and remaining limits |
| --- | ---: | --- |
| Audit logging | 9 | Parameterized storage, update/delete triggers, output hashes/bounds, attempted/terminal events, fail-closed audit errors; separate privilege isolation outstanding |
| Authentication and sessions | 8 | Bootstrap password change, hashing, revocation, migration, persistent login throttling, ownership, reauthentication |
| Authority modes | 8 | Scoped expiry, production denial, malformed scope denial, owner-bound pause/resume/stop; live enforcement not proven |
| Backup jobs | 6 | Typed job IDs, session-bound one-use approvals, malicious IDs denied; no real dump generated or restored |
| Change transactions | 18 | Deterministic plans, approval use/expiry, revisions, skip-host, order, locks, canary failure, stepwise simulation, backup-before-approval |
| Conversation history | 7 | Ordering, validation, provider persistence, individual/all deletion; browser interactions untested |
| Host configuration | 14 | Exact allowlists, thresholds, atomic persistence, malformed inputs, host isolation |
| Credential vault | 1 | Encryption at rest and deletion; key-loss/rotation scenarios not covered by this one test |
| Executor and policy | 24 | Fixed diagnostics, injection rejection, bounded output, port-command fallback; transport doubles, not live SSH |
| Fleet diagnostics | 3 | Bounded snapshots, metric parsing, failed-host isolation, concurrency/timeout validation |
| Fleet history | 1 | Persistent bounded host-scoped history |
| SSH forced-command gate | 49 | Exact authorized command shapes, escape denial, absolute binaries, policy ownership/mode checks; not deployed escape testing |
| Host CLI | 3 | Add/list/remove, duplicate refusal, unsafe value rejection |
| Managed files | 11 | Named paths, traversal/device/metadata denial, encoding/size/validator checks, TOML roundtrip; actual atomic writes and race resistance unverified |
| VM onboarding | 7 | Double key verification, cancellation, changed-key refusal, exact removal, vault storage; no new VM enrolled |
| Packages | 13 | Fixed APT preview, allowlisted IDs/versions, held-package rejection, canary stopping, policy validation; actual installs unverified |
| Phase 22 adversarial/recovery | 12 | Prompt-like data, approval replay, cross-session/user denial, restart interruption, host locks, production boundary, persisted-stage drills; simulated failures |
| Playbooks | 3 | Fixed ordered steps, invalid IDs, sanitized failure with later-step stop |
| Preflight | 2 | Valid and missing local prerequisites; inaccessible-file exception separately observed |
| Presentation | 4 | Verbatim raw output first, bounded failure/truncation summaries, ordering, empty-summary rejection |
| Privileged helper | 12 | Typed fixed executable mapping, root-owned backup executable checks, malicious/unknown inputs; actual root execution untested |
| Rate limiting | 7 | Sliding-window recovery, isolated budgets, invalid bounds |
| Autonomous recipes | 4 | Nginx typed expansion, non-lab denial, unknown recipe/incomplete policy denial; planner advertises `live_execution=False` |
| Recovery store | 3 | Opaque snapshots, checksums, expiry/tampering denial, idempotent simulated restoration, capacity/retention |
| Restart remediation | 4 | Allowlist, reauthentication approval binding, expiry, post-state verification; no remote restart performed |
| Security posture | 4 | Fixed auth-log pattern, findings, allowlist skipping, isolated failure, timeout validation |
| Security review | 6 | Audit completeness, policy denials, prompt injection kept as raw data |
| MCP adapter | 11 | Typed tools/schemas, bounded parameters, fixed routing, raw output, denied paths, rate limits; no external MCP-client stdio session |
| Service lifecycle | 14 | Configuration dependency, impact, required health evidence, rollback decisions, ID/policy validation; simulated lifecycle |
| SSH transport | 5 | UTF-8 output byte limits, full bounded output, invalid limit rejection; no live handshake/disconnect test |
| Web/API and model adapters | 12 | Host pinning, unknown-host denial, provider validation, routes, CORS, auth/CSRF/revocation, backup approvals, model timeout; provider responses mocked |

The extra API smoke script uses a disposable database and an empty fleet. It exercises every registered protected API method for unauthenticated denial, every protected mutating method for missing-CSRF denial, and each non-parameterized GET after login/password change. These checks do **not** test every route's successful business workflow.

## Confirmed findings and improvements

### High priority: workflow progress can misrepresent execution

`ui/app/changes/page.tsx:31–39` adds a completed stage for every evidence record without checking its status. It also marks Activate complete when any validation evidence exists and the plan contains a service action. A direct execution of the extracted function with failed validation and a restart action returned `Inspect, Plan, Preview, Validate, Activate`, despite no activation record.

Use explicit successful stage states, distinguish failed/running/skipped stages visually, and require actual activation evidence. Add a focused UI-unit regression covering successful validation before activation and failed evidence. This is especially important for an interface intended to make mutation decisions reviewable.

### High priority: frontend quality gates are failing

`ui/app/changes/page.tsx:141` combines typed preview records with a fallback array of `{effect}` objects; subsequent access to optional preview fields produces 25 TS2339 diagnostics. Give the fallback the same explicit preview item type or render it separately.

`ui/app/account/page.tsx:22` supplies `asChild` to a Button wrapping Base UI, whose local type does not support that prop. Use the component's supported composition API or a link styled as a button. Check keyboard focus and resulting HTML after changing it.

Make type checking a required build/CI gate: bundling currently succeeds while these errors remain. Triage UI lint findings instead of treating a successful bundle as frontend validation. Some accessibility warnings originate in generic components and require usage-aware review; they are not all independently proven user-facing defects.

### Medium priority: SQLite connection lifetime is implicit

The isolated smoke run initially completed its requests but failed to delete its temporary database with Windows error 32 (file still in use). Audit, authentication, and chat stores use SQLite connections as transaction context managers, without explicit closing. Such contexts commit/roll back; they do not close connections. Adding garbage collection before smoke-harness cleanup let all 103 checks finish.

Use explicit connection closing (for example, an outer closing context with an inner transaction), or a clearly managed application connection lifecycle. Test file release and repeated requests on Windows. The smoke harness's collection step is a workaround, not a production fix; no load-test claim is made here.

### Medium priority: release status and documentation disagree

README emphasizes early phases and a read-only service despite restart/backup mutations and later simulation workflows. The roadmap labels security posture and identity hardening Planned even though implementation and tests exist. Conversely, Complete for later phases can be mistaken for operational readiness when the completed scope is simulation.

Maintain separate implementation, automated verification, and live-lab acceptance states per feature. Explicitly label simulated evidence in the UI and docs. Update the earlier functional-validation report rather than treating its 10 September results as current evidence.

### Medium priority: finish live acceptance before broad rollout

On explicitly disposable Linux VMs, validate forced-command and sudo boundaries, host-key changes, all diagnostic binaries, real restart verification, dump creation plus restore, disconnection handling, and real rollback drills. Capture audit evidence for each. Real package/file/service writers and signed recipes remain unfinished; recipe versioning alone is not signature verification. The current Nginx recipe expands install, file write, and activation actions; it does not by itself implement the full documented inspect/enable/recovery lifecycle.

### Lower priority: maintainability and operational checks

Resolve 15 Ruff findings (12 reported as safely auto-fixable), split the large web module into feature routers, and replace dense single-line UI workflows with smaller typed components. Add a CI command for Python tests, lint, TypeScript, UI lint, and build. Add browser workflow tests and branch coverage reporting; no coverage percentage is available in this review. Handle permission errors in preflight with a bounded actionable message.

## Not validated in this review

- Browser rendering, keyboard interaction, responsive layout, and full authenticated click-through of the 13 UI routes. The build covers compilation, not browser behavior.
- Real SSH connections, forced-command installation, sudo/root policy, Linux symlink races, network partitions, or actual process-kill recovery during a remote mutation.
- Live OpenAI, Gemini, or local model responses, provider billing/error behavior, and external MCP client integration.
- Real database dumps/restores, package installation/removal, file writes, service activation, or remote rollback.
- Load/concurrency endurance, dependency vulnerability advisories, external audit tamper resistance, or numerical statement/branch coverage.

Therefore, **every existing automated test ran**, and each implemented feature area was inventoried, but **every functionality is not end-to-end certified**. Remote mutation was not appropriate to infer from a general testing request without identifying disposable targets and allowed disruption.

## Reproduction and evidence

From the repository root:

```powershell
python -m pytest -q --junitxml=docs/validation-2026-09-17/pytest.xml --basetemp=.test-tmp-review-20260917
python docs/validation-2026-09-17/api_smoke.py
python -m ruff check src tests --output-format concise
python -m pip check
python -c "from sysadmin_mcp.preflight import main; raise SystemExit(main())"
```

From `ui`:

```powershell
npx tsc --noEmit
npm run lint
npm run build
```

Artifacts: [individual pytest results](validation-2026-09-17/pytest.xml), [API smoke results](validation-2026-09-17/api-smoke.json), and [reusable isolated API smoke script](validation-2026-09-17/api_smoke.py).

Recommended next milestone: correct workflow progress, make all frontend quality gates green, explicitly close database connections, then run browser workflows and a documented disposable-VM acceptance campaign before enabling additional live automation.
