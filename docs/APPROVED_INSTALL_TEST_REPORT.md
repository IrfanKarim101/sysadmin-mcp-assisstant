# Approval-based installation validation — 2026-09-21

## Results

| Check | Result |
| --- | --- |
| Full backend regression suite | **402 passed**, 56.86 seconds |
| Installation-specific suite | **29 passed**, including 12 added edge cases |
| Ruff on changed/new Python modules, scripts and corresponding tests | **Passed** |
| Frontend lint on Software, Dynamic/Host scripts and MCP connection component | **Passed** |
| Production frontend build (`npm run build`) | **Passed**, after UI corrections |
| Python wheel build | **Passed** with isolated build dependencies |
| Wheel content/template smoke test | **Passed** for both Nginx and Tomcat; new modules included and both installer/verifier scripts load and compile from extracted wheel |
| `git diff --check` | **Passed** |
| Repository-wide TypeScript check | **Failed** on existing Account `asChild` and Changes action-preview typing errors |
| Repository-wide Python lint | **13 existing findings remain** in unchanged Changes/Services implementation and older tests |
| Repository-wide frontend lint | **Failed** on existing shared-component accessibility, hooks, deprecation and typing findings outside the focused new pages |
| Live fresh installation through MCP | **Not performed**: selected VM already has both applications and lacks execution prerequisites; user requested no changes |

Commands used include `python -m pytest -q`, `python -m ruff check`,
`npx tsc --noEmit --incremental false`, `npm run lint`, focused `npx oxlint`,
`npm run build`, and `python -m pip wheel . --no-deps`.
The final machine-readable backend results are in
`../.run/new-changes-final-pytest.xml`.

The initial wheel attempt without build isolation found no installed Hatchling.
An isolated build then downloaded the declared build dependency with approved
network access and succeeded. This did not require a project dependency change.

## Coverage

- Actual MCP tool dispatch and delegated API preparation in Guided and Autonomous Lab.
- No execution before user approval, including generic host scripts.
- Password, CSRF, host scope, digest and one-use/replay enforcement.
- Stopped/replaced authority, action budgets, locks and existing sandbox isolation.
- Exact version validation; unsupported products, upgrade and Podman execution rejected.
- Independent verification and truthful failure reporting.
- Legacy job database migration and mandatory approval for pre-migration host jobs.
- 900-second host-job support without widening the 120-second isolated sandbox limit.
- Refusal before privileged commands for existing configuration, symlinks, occupied
  ports, insufficient disk space, existing units, missing tools and unsupported architecture.
- Stop without retry after sudo, DNF, Nginx syntax or service activation failure.
- Refusal to activate when the installed version differs from the reviewed version.
- Wheel packaging and runtime template loading.

Remote command behavior in the automated installer tests is simulated. These tests
are not evidence of a successful live fresh installation or of a browser interaction test.

## Corrections made during validation

- Corrected effect dependencies in the job-review page so polling follows the current
  job and API endpoint.
- Used semantic status output elements in the script-review and MCP connection pages.
- Sorted imports and removed an unused import in changed Python files; documented
  the intentional sanitized exception boundary for streamed host-script errors.
- Added 12 regression cases for host preconditions, failure sequencing and legacy jobs.

## Read-only checks on the user-selected VM

Target: enrolled `Test-VM`, `192.168.1.20`, root SSH account. Connected with the
saved credential and pinned host key. No credential values were printed.
User explicitly selected **Check this VM without changes**.

| Observation | Evidence |
| --- | --- |
| Operating system | Rocky Linux 9.7, x86_64 |
| Existing Nginx | RPM installed; nginx reports version 1.20.1 |
| Nginx service | Active/running, main PID 996, packaged systemd unit |
| Nginx configuration | `nginx -t` passed |
| Nginx local root URL | HTTP **403** on port 80; does not meet the new fresh-install verifier's HTTP 200 requirement |
| Existing Tomcat | Active/running, main PID 907; custom unit in `/etc/systemd/system`, installation under `/opt/tomcat`; no Tomcat RPM |
| Tomcat local root URL | HTTP **404** on port 8080; server responds, but this does not establish a deployed application's health |
| Python | System Python 3.9 installed; Python 3.11 package/command absent |
| MCP host helper | Not provisioned at the expected paths |
| Saved host classification | Production; left unchanged |

No package installation, service restart, repository edit, host reclassification,
helper provisioning, account creation or application configuration change was made.
The existing applications were left intact. The HTTP results describe their current
state; they are not failures caused by the new installation code.

A successful fresh-install acceptance run remains outstanding. It requires a clean
development/disposable-lab Rocky 9 VM, a current Python 3.11+ host helper, a non-root
execution account with reviewed sudo permissions, and approval of each installation job.
