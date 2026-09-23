# Guided and Autonomous Lab completion report

## Implemented

- Console requests use the server's active mode and authenticated authority owner.
- Guided Lab generates a persisted, editable script and verifier for one-use,
  password-confirmed execution. Edits require a new digest.
- Autonomous Lab generates, executes and verifies one job per request under explicitly
  armed Host scripts capability, host scope, lifetime, budget and concurrency.
- Target and capability errors explain the mismatch. The banner shows actual VM and
  capability names and supports Change scope.
- Host scripts are separate from rootless Dynamic sandbox and legacy recipe simulations.
  Production/staging execution is rejected; session-bound jobs are audited and not replayed.

## Local validation

| Check | Result |
| --- | --- |
| Complete backend suite including MCP and generation regressions | 373 passed |
| Focused host-mode suite after scope changes | 9 passed |
| UI production build | Passed |
| Ruff on new helper/provisioning/test modules | Passed |
| Diff whitespace check | Passed |
| Full TypeScript check | 26 existing Account/Changes errors; none in new mode files |

## Native MCP correction

The earlier manual Olaf provisioning did not demonstrate autonomous agent installation.
The native stdio MCP interface now has opt-in scope, prepare, execute and evidence tools
backed by the same web-session authority. Integration tests dispatch real MCP tool calls
through delegated authenticated endpoints into a simulated VM runner. Guided execution
is denied until the human approves in the UI; Autonomous execution consumes the armed
budget and cannot replay a job. Tokens cannot arm authority or access ordinary APIs and
are invalidated by rearming/logout/restart. Local backend startup and UI build passed.
The final focused MCP/server suite passed 19 tests after credential-provider wiring.
No VM was installed or configured during this correction. Live LLM-generated installation
acceptance remains separate from these simulated-runner tests and prior manual provisioning.

## Gemini generation fix — 2026-09-20

The original failure was reproduced: Gemini returned Markdown-fenced JSON, while
the app required bare JSON. Generation now requests a strict JSON schema for Gemini
and safely accepts one complete JSON code block. Python syntax and field validation
still apply; prose, incomplete drafts and malformed data are rejected before execution.
Generation has a 90-second bound and at most one SDK retry for transient failures.
Timeout, connectivity, quota, provider status, truncation and format errors have
distinct operator messages. Failed chat requests now show a red failure icon.

All 373 backend tests and the UI production build passed. Live generation-only
acceptance used an isolated test app with a fake VM runner: zero VM executions and
zero diagnostics. The configured model, `gemini-3.6-flash`, returned HTTP 503 with
an explicit high-demand message. A separate JSON-object request returned the same
503, confirming that the outage was not specific to schema mode. Successful live
generation remains unverified until the provider becomes available. No VM software
or configuration was changed during this fix. The configured model was not changed.

Tests cover mode routing, Guided approval, Autonomous execution, CSRF/password,
ownership, target mismatch, lab restrictions, digest/replay, budget, pause, authority
replacement, bounded output and strict verification. Model generation is mocked.

## Live Olaf acceptance

Target: `olaf-ubuntu`, `192.168.0.109`, Ubuntu 25.10, account UID 1001.

1. Installed the root-owned host helper, Python dependency environment, explicit lab
   account policy and persistent runtime-directory configuration.
2. Ran read-only OS inspection through HostSSHRunner and the real helper. Execution
   and independent verifier exited 0 and the checks passed.
3. Installed `nginx` and `nginx-common`, version `1.28.0-6ubuntu1.8`. No other packages
   were upgraded or removed. Used packaged/default site configuration; no custom domain,
   TLS or reverse proxy was configured.
4. Validated configuration, enabled and started Nginx, and observed local HTTP 200.
5. Installed a visudo-validated rule for exact Nginx maintenance commands only.
6. Repeated checks through the actual noninteractive host-script helper:
   `sudo -n /usr/sbin/nginx -t` passed. The independent verifier confirmed Nginx active,
   enabled at boot and HTTP 200. General `sudo -n /usr/bin/true` remained denied.
7. Restarted the local backend after confirming no script jobs were running. Startup
   completed successfully. Authority resets to Observe and must be re-armed.

Provisioning was an explicit administrator operation, not an LLM-generated installation.
Live acceptance exercised SSH/helper/verifier execution. Authenticated chat orchestration
was tested with mocks; a full live LLM chat run remains untested.

## Operator steps

Refresh the UI, select **olaf-ubuntu** and its chat, then arm Guided Lab or Autonomous
Lab with **Host scripts** and reauthenticate. Old package/service-only authority does
not grant generated execution. Guided requests open review; Autonomous requests run
once and return evidence. General sudo remains unavailable on Olaf.

## Limits

- Custom Nginx sites need domain/upstream/TLS settings and reviewed file permissions.
- Rocky Linux 9, Tomcat, Kafka, MySQL, MongoDB and data-preserving upgrades were not live-tested.
- Generated verification covers its programmed checks, not every data-integrity property.
- Pause/stop does not undo completed changes or stop already-started services.
  Privileged/detached children can outlive cancellation.
- Jobs have a 120-second execution/verification limit. Failed mutations are not retried
  automatically; long installs need a separately planned workflow.
