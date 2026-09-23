# Evesdropctl

A security-first MCP service for **read-only** diagnostics on approved Linux
hosts over SSH. The complete design and delivery plan are in
[`project_context.md`](project_context.md) and
[`project-phases.md`](project-phases.md).

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

Phase 1's executor policy and typed MCP adapter are implemented. `ReadOnlyCommandPolicy` builds a
small, fixed set of argument vectors for ports, services, resource snapshots,
allowlisted log reads/searches, and active users. `ReadOnlyExecutor` applies
uniform output bounds, while the AsyncSSH implementation remains isolated in
the transport module. The local operator UI adds fleet views, investigation
playbooks, security posture, encrypted VM credential storage, conversation
history, and approval-gated service restart and database-backup jobs.

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

Phase 5 adds a raw-first presentation model and a replaceable summary boundary.
The safe default summary is content-blind, so prompt-like text in logs remains
inert. See [`docs/presentation.md`](docs/presentation.md).

Phase 6 provides validated multi-host TOML configuration, per-host log
allowlists and resource thresholds, plus an atomic `sysadmin-hosts` management
command. See [`docs/host-configuration.md`](docs/host-configuration.md).

Phase 7's local adversarial review covers injection, traversal, audit
completeness, prompt-like log content, and output amplification. Findings and
remaining live-host checks are recorded in [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md).

Phase 8's MVP cut adds per-session rate limiting, clear safe policy errors, and
`sysadmin-preflight`. The deployment sequence and acceptance criteria are in
[`MVP_RUNBOOK.md`](MVP_RUNBOOK.md).

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

Native fresh installs of Nginx and Tomcat on Rocky Linux 9 are available from Software management or the MCP `prepare_software_install` tool. Each job requires administrator review and password confirmation before executing, including in Autonomous Lab mode. See [installation workflow](docs/APPROVED_SOFTWARE_INSTALL.md) for prerequisites, supported versions, verification and limitations.
