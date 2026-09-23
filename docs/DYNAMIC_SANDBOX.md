# Dynamic sandbox mode

## What is implemented

Dynamic sandbox is a separate authority mode for development/disposable-lab
hosts. The Dynamic scripts page can generate Python and a verifier using the
configured OpenAI, Gemini, or local provider; alternatively an operator can
write both scripts directly. Generation never executes code.

1. An administrator arms Dynamic sandbox for exact hosts, a 15–60 minute
   lifetime, an action budget and concurrency limit, using fresh reauthentication.
2. Prepare syntax-checks and persists the script, verifier, target, timeout,
   digest, owning authenticated session, and authority generation ID. Review
   expires after ten minutes. Any edit requires a new prepared job.
3. Run requires the exact digest and fresh administrator reauthentication.
   Each job can run once. The server rechecks authority, consumes budget,
   records an audit attempt, and takes a host/concurrency lock before SSH.
4. SSH invokes one fixed helper, passing bounded JSON on stdin. It does not
   interpolate generated code into a host command or send credentials to the model.
5. The helper creates a rootless Podman container from an administrator-approved,
   pre-pulled image pinned by digest. It runs the script and verifier in separate
   Python interpreter processes sharing only the container's ephemeral `/work`.
6. Raw bounded stdout, stderr and exit codes are stored with the result. A
   `verified` result requires successful non-truncated execution and a separate
   successful verifier emitting nonempty, strictly boolean, all-passing checks.
7. The helper removes the container on completion, failure or cancellation.

Example verifier output:

```json
{"checks":[{"name":"Output contains the expected records","passed":true}]}
```

Verification means the reviewed assertions passed. It is not a proof that
model-generated code is correct or that the model chose adequate assertions.
An operator must review the verifier as well as the main script.

## Intentional boundaries

- Python only; no raw host shell, sudo, host mounts, SSH forwarding or network.
- Read-only container root; image-declared volumes are ignored. `/work` is a
  32 MiB noexec/nosuid/nodev tmpfs and is destroyed afterward.
- UID 65534 inside the rootless container, all capabilities dropped,
  no-new-privileges, default seccomp and SELinux isolation retained.
- 256 MiB memory, 1 CPU, 32 processes, 1–120 seconds total execution time,
  32 KiB retained per output stream. No image pulls during execution.
- Generated code can create subprocesses **inside** these container limits;
  Python syntax checking is never the security boundary.
- No automatic repair/retry of failed code. Preparing a replacement creates a
  new digest and consumes another action if run.
- The existing diagnostic MCP stdio tools and read-only SSH gate are unchanged.
  This first version is available through the web/API Dynamic scripts workspace.
  It is not a generic unrestricted MCP shell tool.

This mode cannot install Nginx, databases or packages on the real VM, inspect
the VM's host filesystem, or validate real VM services. Those tasks require the
separate native/software execution adapters. Do not use sandbox output as
evidence that a real VM was modified.

## Provisioning the later Linux VM

No VM was enrolled or modified during implementation. The host runner is real
code, but live Podman/SSH execution and isolation still require acceptance on
the operator's disposable Rocky 9 VM.

Use a dedicated unprivileged SSH account, with no general sudo privileges, and
an administrator-maintained installation of this Python package (Python 3.11+
is required). The helper entry point must be installed at
`/usr/local/bin/sysadmin-dynamic-sandbox`; its executable, Python environment,
modules, parent directories, and SSH gate must not be writable by the runner.
Rocky 9's default Python may need a separate supported Python installation.

Install Podman with working rootless storage, subordinate UID/GID mappings,
cgroups v2 delegation, SELinux, and a valid `/run/user/<uid>` directory owned by
the runner. Prepare the approved Python image as that account and record its
immutable digest. The image must provide `python3` and the standard library;
the helper overrides its entry point. Verify the selected Podman release
supports all flags, including the container lifetime timeout.

Copy `hardening/dynamic-sandbox-policy.example.json` to
`/etc/evesdropctl-dynamic.json`. Keep it root-owned and not group/world writable;
set the actual unprivileged UID, development/disposable-lab classification,
approved image digest and `enabled: true` only after enrollment review. The
supplied example is intentionally disabled and cannot execute.

Configure this account's SSH forced command as the root-owned
`sysadmin-dynamic-command` entry point, with OpenSSH `restrict` and no
interactive shell, forwarding, agent forwarding or user startup commands.
This **opt-in** gate admits the one exact sandbox helper command and delegates
other requests to the existing read-only gate. Do not replace gates on unrelated
hosts or grant this account an unrestricted shell. The original read-only gate
will correctly reject dynamic jobs until the opt-in helper/gate is installed.

Host policy is independent of the application host classification. Both must
allow lab execution. The controller reuses the enrolled host's pinned SSH
identity and vault credentials. Do not disable SSH host-key verification.

## Cancellation and recovery

The controller polls authority while a job runs. Pause, logout, expiry, stop,
emergency stop, host-policy changes or rearming invalidate continued authority.
Cancellation signals the SSH helper; the helper attempts container cleanup.
Independent Podman lifetime limits bound orphaned runs if the connection or
backend disappears. Stop is best-effort remote cancellation, not an instantaneous
guarantee during a network partition. Cleanup failures produce failure, not success.

The host serializes helper invocations using an account-local file lock. A
backend restart marks running jobs interrupted and never replays them. A
stopped container may require inspection if Podman cleanup failed. Do not retry
until the prior sandbox is confirmed stopped. Run a single web worker; the
existing authority service is process-local.

## Acceptance checklist

Run the included /work example and prove its verifier fails when the output
is wrong. Also prove no host-file modification, outbound network, sudo or
privilege escalation; bounded output and memory; process/time limits; cleanup
after timeout, disconnect, backend restart and emergency stop; rejection of
wrong SSH identity, disabled host policy, root execution, wrong UID, mutable
image tags, production classification, stale approvals and replay. Check the
audit attempt and terminal outcome plus saved raw evidence for each run.

The local automated tests exercise authority, job lifecycle, verifier parsing,
real subprocess output bounding, sandbox argument construction, timeout cleanup
with a mocked Podman adapter, and web authentication boundaries. They do not
substitute for this Linux acceptance checklist.

Podman isolation options reference:
[official podman-run documentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html).
