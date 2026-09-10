# Functional validation

Validated on 2026-09-10 against the local application.

| Requirement | Result | Evidence |
|---|---|---|
| Fixed typed diagnostic commands; no raw executor | Pass | Policy, executor, MCP, and forced-command tests |
| Per-host log allowlists and bounded output | Pass | Traversal, injection, line, byte, and transport-cap tests |
| SSH transport isolated from policy | Pass | Local fake-transport policy and service tests |
| Durable SQLite action and conversation history | Pass | Append-only audit and chat-store tests |
| Authentication, CSRF, timeout, first-login change | Pass | Auth/API tests and browser keyboard-submit check |
| Multi-VM enrollment and explicit host-key trust | Pass locally | Deterministic onboarding tests; live second VM not enrolled |
| Fleet snapshots and failure isolation | Pass locally | Fleet concurrency, timeout, circuit, and history tests |
| Fixed investigation playbooks | Pass | Routing and evidence-separation tests |
| OpenAI/Gemini provider selection | Pass structurally | Schemas and adapters tested; live calls require configured keys |
| Allowlisted service restart | Pass locally | Reauthentication, preview, replay denial, audit, and verification tests |
| Fixed database backup job | Pass locally | Reauthentication, fixed ID, malicious input, replay, helper, and audit tests |
| Live Linux forced-command boundary | Pending live validation | Deploy and run the hardening escape checklist on the disposable VM |
| Live database dump creation | Pending host setup | Install the root-owned script/helper/policy and verify a real dump artifact |

## Release assessment

The local MVP functional boundary passes. Production readiness remains blocked
until the Linux host-side hardening and backup job are deployed and the live
escape checklist passes. Phase 9 certificate/file-metadata work, Phase 10
tags/baselines/notifications, and Phase 13 MFA/OIDC remain future scope rather
than completed requirements.
