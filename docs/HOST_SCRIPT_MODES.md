# Guided and Autonomous Lab host scripts

These modes now connect the console to generated Python execution on the selected
lab VM. This is real host execution, separate from Dynamic sandbox and the older
simulation-only Changes recipe workflows. Software management now prepares approved native Nginx/Tomcat installation jobs.

## Workflow

1. Enroll the VM and classify it as development or disposable lab. Select its chat.
2. Provision the helper below. Production and staging cannot use Host scripts.
3. Arm Guided Lab or Autonomous Lab, select the VM, explicitly select **Host scripts**,
   set duration, job budget and concurrency, and reauthenticate.
4. Submit a request in that VM's chat. Mentioning a different enrolled VM is rejected;
   select that VM rather than relying on a name in the message.
5. Both Guided and Autonomous Lab generate a script and verifier and link to Host scripts for review.
   Review both, edit if necessary, prepare a new digest, then reauthenticate to approve and run once.
   After approval, execution and verification proceed automatically. Failed mutations are never automatically retried.
6. Inspect stdout, stderr, exit status and verifier JSON. Only a successful execution
   and nonempty, strictly true checks produce `verified`. That means the generated
   assertions passed, not a guarantee that all requirements or data integrity were tested.

## Native MCP client

The web console orchestrates its own model calls. A separate MCP client (an agent
connected to `sysadmin-mcp` over stdio) now has an opt-in execution bridge as well:

1. Arm a Host scripts session in the web UI.
2. Open Host scripts and click **Create MCP connection**. This delegates only that
   session's authority and revokes any previous connection for the session.
3. Copy the token into the MCP client's environment as `SYSADMIN_MCP_EXECUTION_TOKEN`.
   Keep it out of model prompts and source control. Start the server with
   `sysadmin-mcp --enable-host-scripts`. The backend must be running on the same machine;
   `--execution-api http://127.0.0.1:8765` is the default.
4. The agent calls `get_execution_scope`, generates Python plus an independent verifier,
   and calls `prepare_host_script`, or uses `prepare_software_install` for Nginx/Tomcat.
   In every mode it returns the review link to the human. `run_host_script` rejects direct execution; approval stays in the UI.
5. The agent reads evidence with `get_host_script_job` and reports the observed result.

The MCP agent cannot arm a mode, increase its budget, change host scope, or approve a
host job. Approval stays in the authenticated UI in every mode. Pause blocks MCP execution;
logout, expiry, rearming and backend restart revoke the delegation. Tokens cannot access
ordinary web APIs. Loopback-only transport rejects redirects and ignores HTTP proxies.
Without the flag, the MCP server retains its existing read-only diagnostic tools.

No manual server installation performed by the development assistant counts as an
agent workflow test. The MCP integration tests exercise real MCP tool dispatch, the
authenticated delegation endpoints and the job lifecycle with a simulated VM runner.

Host scripts allow up to 900 seconds for execution and verification; generated drafts default to 30 seconds and MCP generic scripts to 120 seconds. Deterministic installation jobs use 900 seconds. The isolated sandbox remains capped at 120 seconds. Existing remote helpers must be updated for the longer host limit. A budget action is one
script job, not each shell command inside it. Generated Python may invoke subprocesses.
SSH pins the enrolled host identity and always invokes a fixed helper. Model text is
passed on stdin, never interpolated into the SSH command. Existing permissions and
sudo policy apply; arming a mode does not grant Linux root privileges.

## Provisioning a lab VM

Provisioning is an administrator deployment step; the application does not silently
install or elevate its own helper. Olaf was explicitly provisioned during acceptance
testing; other enrolled VMs still require this administrator deployment step.

For a new installation, copy a reviewed repository to the lab VM and run:

```sh
sudo python3 scripts/install_host_helper.py --user olaf --environment disposable_lab
```

This requires Python 3.11+, venv/pip support and access to the Python package index.
It installs a root-owned helper and Pydantic in `/opt/evesdropctl-host`, the explicit
account policy and runtime directory below. It refuses to overwrite an existing
installation and does not grant sudo privileges or change SSH configuration.

- Install the reviewed project package in a root-owned Python 3.11+ environment.
  The `sysadmin-host-scripts` console entry point must be available at
  `/usr/local/bin/sysadmin-host-scripts`, with root-owned, non-writable code and parent
  directories. Do not point it at a user-writable development checkout.
- Install `hardening/host-scripts-policy.example.json` as
  `/etc/evesdropctl-host-scripts.json`, owned by root with mode 0644 or stricter.
  Set the actual nonroot SSH UID, lab environment, and `enabled: true` after review.
- Provision `/run/evesdropctl-host-scripts` root-owned mode 0755 and a child named by
  that UID, owned by the SSH account, mode 0700. Persist them with systemd tmpfiles.
  For example, substitute the real UID, username and group in these tmpfiles entries:

  ```text
  d /run/evesdropctl-host-scripts 0755 root root -
  d /run/evesdropctl-host-scripts/1001 0700 lab-agent lab-agent -
  ```

- If using a forced SSH command, opt into `sysadmin-dynamic-command`. That gate now
  recognizes both the rootless sandbox helper and the host-script helper by exact path;
  all other requests still use the read-only gate. The default gate is unchanged.
- Choose the account's Linux permissions explicitly. Generated installation scripts
  use `sudo -n` and fail if the account lacks the required permission. Broad sudo access
  means broad host control; Host scripts is not a package/service allowlist or sandbox.
  Never reuse a production credential to enable this feature on a lab VM.
- Test first with a harmless request such as reading `/etc/os-release`, then a controlled
  service change on a disposable snapshot. Test SSH disconnect, timeout, pause, expiry,
  invalid verification, and failed privilege escalation before relying on unattended use.

## Failure and data behavior

Jobs are owner/session-bound, digest-bound, one-use, expiring and tied to the exact
authority generation. Rearming invalidates reviews. API and host locks prevent
overlapping host-script jobs; restart marks interrupted jobs and never replays them.
Pause/stop/expiry cancels the active SSH job; the helper terminates its ordinary process
group. This is best effort: privileged or detached processes and started services can
outlive it. Stop is not rollback. Network loss can leave uncertain remote outcomes;
inspect the VM before retrying. Independent backend workers are not supported.

The generation instructions demand preservation of data/configuration, backups before
edits, and stopping when a safe upgrade path cannot be established. These instructions
are not a deterministic database upgrade engine. No live MySQL/MongoDB/Kafka data
preservation guarantee is made. Guided review and verified backups remain necessary
before applying generated upgrades to valuable data.

## Validation

Automated tests cover mandatory approval in Guided and Autonomous modes, selected-host mismatch,
session/password/CSRF requirements, job replay, budget, pause, lab-only scope, strict
verification and existing sandbox isolation. Local UI production build is checked.
Live helper execution and independent verification passed on Olaf (Ubuntu 25.10).
Nginx installation, configuration validation, service enablement and local HTTP checks
also passed there. Rocky Linux and other software upgrades have not been live-tested.

For Ubuntu lab Nginx provisioning, `scripts/provision_nginx_lab.py` is a separate
root-run administrator action. It installs the packaged server without replacing site
configuration, checks HTTP, and installs a validated sudoers entry permitting only
the exact Nginx install/config-test/service commands enumerated in the script. It does
not permit arbitrary configuration-file writes or a general root shell. This policy
was installed on Olaf; custom sites require explicit settings and reviewed file
permissions. Do not run the Ubuntu provisioning script on Rocky Linux.
