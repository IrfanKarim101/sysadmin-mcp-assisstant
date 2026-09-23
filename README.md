# Evesdropctl

An MCP service and web console for Linux diagnostics over SSH, with optional
**user-approved automation on lab hosts**. Observe mode is read-only by default.
Host changes require explicitly armed authority and approval of each job.

This README describes the current implementation.
[`project_context.md`](project_context.md) and
[`project-phases.md`](project-phases.md) retain the original design and phased
roadmap; some early descriptions predate the optional host-script execution path.

## Web console authentication

The local console starts with the temporary account `admin` / `admin`. Its first
login is restricted to changing that password; use at least 12 characters.
Passwords and session tokens are salted or hashed in `data/audit.db`. Sessions
use an HttpOnly cookie, CSRF protection, a 30-minute idle timeout, and an
8-hour maximum lifetime. The top navigation provides separate **Console** and
searchable **History** views plus explicit sign-out.

Conversations are scoped to one VM. Select a VM in Console, choose one of its
saved conversations, or use **New chat** for a fresh conversation (saved with
the first message). History includes a VM filter and **Continue this chat**.
Switching VMs cannot reuse a conversation belonging to another VM. On backend
startup, older mixed conversations are separated using the host metadata on
user messages, retaining their following replies and message order. Messages
without host metadata retain their recorded session host. The console uses
frosted glass surfaces with an opaque fallback for reduced transparency.

## Current status

**Updated September 23, 2026.** The project has working diagnostics and an
implemented approval-based automation workflow. Fresh Rocky 9 installation
acceptance is still pending; implementation and automated tests do not establish
production readiness.

| Area | Implemented behavior | Validation or limitation |
| --- | --- | --- |
| Diagnostics and MCP | Typed SSH diagnostics for resources, services, ports, logs, users, containers and inventory; bounded output and audit records | Default MCP server remains read-only |
| Operator console | Authentication, encrypted VM credentials, SSH key trust, VM-scoped chat/history, fleet views, playbooks and security posture | ChatGPT, Gemini and compatible local model support |
| Typed remediation and backups | Approved service restarts and host-policy database backup jobs | Require separately provisioned host policies and permissions |
| Host scripts | Generate or prepare Python and an independent verifier; persist, review, approve, execute and record results | Lab-only; every job requires approval in both Guided and Autonomous Lab modes |
| Software installation | Fresh native Nginx and Tomcat installs on Rocky Linux 9 from signed baseos/appstream RPMs, with exact upstream version selection | Automated coverage passes; successful live fresh-install acceptance remains outstanding |
| Dynamic sandbox | Reviewed Python in a separate rootless, offline container | Cannot install host packages or administer the VM |
| Changes and versioned recipes | Planning, previews, simulation, approval and simulated recovery workflows | Older Changes/recipe paths remain simulation-only; distinct from executable host jobs |
| Other software workflows | Upgrade and Podman plans; Kafka, MySQL and MongoDB catalog entries | Planning-only; no deterministic live installers or validated data-preserving upgrades |

### Approval and execution contract

```text
Prepare job → Review host, script and verifier → User approves
→ Execute once → Independently verify → Inspect recorded evidence
```

Arming a mode does not approve a host job. The operator must approve the saved
job in the authenticated web UI with password confirmation. MCP can prepare
jobs and retrieve their results, but cannot approve or start them itself.
Jobs are bound to the operator session, host, script digest and authority lease,
with expiry, one-use execution, budgets and concurrency controls.

Host scripts run with the selected SSH account's real permissions; they are
**not a sandbox**. They require a development/disposable-lab host, a root-owned
Python 3.11+ helper, a non-root execution account and separately configured
noninteractive sudo permissions where needed. Host jobs allow up to 900 seconds;
isolated sandbox jobs remain capped at 120 seconds. Failure or stop can leave
partial changes; no automatic rollback or mutation retry is promised.

### Latest verification

The latest recorded validation is **September 21, 2026**; these results were not
rerun for this documentation update. See the
[full test report](docs/APPROVED_INSTALL_TEST_REPORT.md).

- **402 backend tests passed**, including 29 installation-specific tests.
- Production UI build, Python wheel build and packaged-template smoke checks passed.
- Lint checks passed for the changed Python code and the new software/script pages.
- Repository-wide checks are not all green: existing TypeScript errors remain in
  Account and Changes pages, alongside broader Python/frontend lint findings.
- Live checks on the selected Rocky 9.7 VM were read-only: both existing services
  were running, Nginx configuration validation passed, and their root URLs returned
  HTTP 403 (Nginx) and 404 (Tomcat). These responses do not prove application health.
  No installation or VM configuration changes were performed.

### Remaining work

1. Complete fresh Nginx and Tomcat installation acceptance on a clean Rocky 9 lab
   VM through the actual MCP preparation and UI approval workflow. The previously
   inspected VM already has both applications and lacks Python 3.11 and the host helper.
2. Resolve the repository-wide TypeScript and lint findings.
3. Complete remaining host-hardening deployment and live escape checks before
   claiming that deployment's security acceptance; see [hardening](hardening/)
   and [security review](SECURITY_REVIEW.md).
4. Implement and validate upgrade preservation/restore, Podman deployment and
   additional software installers before enabling their execution.

The diagnostic executor still accepts fixed typed requests, not arbitrary shell
commands. Exact absolute log paths are configured per host; globs and traversal
are rejected. Diagnostic log requests are capped at 500 lines, and command output
is capped at 2,000 lines and 256 KiB per stream with an explicit truncation flag.
The separately enabled host-script path accepts reviewed Python, which may launch
subprocesses under the account's permissions.

Implementation details: [MCP server](docs/mcp-server.md),
[audit records](docs/audit.md), [host configuration](docs/host-configuration.md),
[presentation](docs/presentation.md), and [deployment runbook](MVP_RUNBOOK.md).

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

## Local operator UI

The **Dynamic scripts** workspace adds optional, reviewed Python execution in
rootless containers on enrolled lab VMs. Arm **Dynamic sandbox**, generate or
write a script and verifier, prepare their digest, then run once with password
reauthentication. It has no VM filesystem/network access and cannot perform host
installations. Provision the separate helper before use; see
[`docs/DYNAMIC_SANDBOX.md`](docs/DYNAMIC_SANDBOX.md) for limits and setup.

Copy `.env.example` to `.env`, then add `OPENAI_API_KEY`, `GEMINI_API_KEY`,
and the SSH credential environment variable referenced by the selected host.
The real `.env` is Git-ignored and keys are never sent to the browser.

Start the local API and UI in separate terminals:

```powershell
sysadmin-web
cd ui
npm install
npm run dev
```

Open `http://localhost:3000`, or `http://<this-PC-LAN-IP>:3000` from another
device on the same private network. Both development services listen on all
interfaces; the browser automatically targets port 8765 on the same host used
for the UI. Credentialed CORS remains restricted to localhost, RFC1918 private
addresses, and exact origins optionally listed in `AGENT_ALLOWED_ORIGINS`.
Use HTTPS and set `AUTH_COOKIE_SECURE=true` before exposing this beyond a trusted
test LAN. The provider switch supports ChatGPT, Gemini, and an OpenAI-compatible
local LLM server configured with `LOCAL_LLM_BASE_URL`, `LOCAL_LLM_MODEL`, and an
optional `LOCAL_LLM_API_KEY`.

### Add VMs from the UI

Select **VM management**, enter an alias, hostname/IP, SSH port, username,
password, and exact allowed log paths. The password is encrypted locally with
AES-256-GCM and is never written to host configuration, logs, browser storage,
or chat history. The first connection
shows the SSH key algorithm and SHA-256 fingerprint. Verify it through the VM
console or a trusted administrator, then choose **Yes, trust key** or
**No, cancel**. Acceptance rechecks the key before atomically updating
`data/known_hosts` and `config/hosts.toml`.

### Database backup jobs

The **Database backups** page runs only typed job IDs enabled for a host.
The browser cannot submit commands, script paths, or arguments. The VM's
root-owned policy maps an ID such as `database-dump` to an exact executable
such as `/root/database-dump.sh`. Runs require Administrator access, password
reauthentication, an explicit confirmation, and a session-bound one-use
approval. Results are bounded and recorded in the SQLite audit history.

See [`hardening/README.md`](hardening/README.md) for host-side installation.

Copy `config/hosts.example.toml` to `config/hosts.toml` only after the test
host is prepared. `config/hosts.toml`, private keys, and SQLite files are
ignored by Git.

## Guided and Autonomous Lab host scripts

Console requests now use the active mode: Guided Lab prepares a script and verifier
for one-use approval. Autonomous Lab also requires approval for each generated host job
under explicit Host scripts authority. These run on the selected lab VM with its
SSH account permissions. A separately provisioned host helper is required.
See [setup, operation, and limitations](docs/HOST_SCRIPT_MODES.md).

### Approval-based software installation

Use **Software management → Native → Fresh install → Prepare installation for
approval**, or the MCP `prepare_software_install` tool. Select an exact upstream
version available in the target's baseos/appstream repositories. Existing
installations and recognized application paths are refused. Required dependencies
may be installed or updated, and the packaged service is enabled and started.
No firewall changes or application deployment are included.

For the MCP preparation tools, first arm Host scripts and create an MCP connection
from the Host scripts page. Set the returned token as
`SYSADMIN_MCP_EXECUTION_TOKEN` in the MCP server environment, then start:

```powershell
sysadmin-mcp --config config/hosts.toml --audit-db data/audit.db --enable-host-scripts
```

The web backend must be running on the same machine. Keep the token out of chat
and source control. Return the job's review link to the operator; after their
approval, read the result with `get_host_script_job`.

See the [installation workflow](docs/APPROVED_SOFTWARE_INSTALL.md) and
[host-script setup](docs/HOST_SCRIPT_MODES.md) for provisioning, verification,
limits and failure behavior.
