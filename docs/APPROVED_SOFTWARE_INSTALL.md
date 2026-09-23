# Install Nginx or Tomcat with user approval

Implemented scope: **fresh native systemd installs on Rocky Linux 9**, using an
exact upstream version available in the VM's existing `baseos`/`appstream`
repositories. Both products use signed RPMs; Tomcat's Java dependency is resolved
by DNF. Upgrades, custom sites, deployed WARs, containers and other products remain
outside this deterministic installer.

## Use it

1. Enroll a development/disposable-lab Rocky 9 VM with pinned SSH host identity.
2. Install the current root-owned host helper using the
   [host provisioning instructions](HOST_SCRIPT_MODES.md#provisioning-a-lab-vm).
   Older helpers capped host jobs at 120 seconds; update their reviewed code before
   using installation jobs, which allow 900 seconds. The provisioning script
   intentionally refuses to overwrite an existing helper.
3. The SSH account must have administrator-provisioned noninteractive sudo
   permission for the exact DNF installation, systemctl enable/start, and Nginx
   syntax-check commands shown in the job. Arming a mode does not grant sudo.
   Do not use the Ubuntu-specific Nginx provisioning script on Rocky.
4. Arm Guided or Autonomous Lab for that VM with **Host scripts**. Choose an
   authority duration that covers review plus up to 15 minutes of execution.
5. In **Software management**, choose native, fresh install, Nginx or Tomcat,
   and the exact upstream version. The version must exist in the selected VM's
   repositories; inspect available versions with `dnf --showduplicates list nginx tomcat`.
   Click **Prepare installation for approval**.
6. Review the host, product/version, full script and independent verifier on Host
   scripts. Enter the administrator password and click **Approve and run once**.
   Installation and verification proceed automatically. Inspect the persisted
   stdout, stderr, exit codes, and verification checks.

With a connected MCP client, call `prepare_software_install` with `host`,
`product` (`nginx` or `tomcat`), and `target_version`. Return `review_path` to the
user and read the result later with `get_host_script_job`. MCP tokens cannot approve
or start host jobs. Generic host scripts also require approval in all modes so
they cannot bypass this requirement. This changes previous Autonomous Lab chat
behavior: chat now prepares a review instead of immediately executing.

## What approval covers

- A fresh install from the VM administrator's configured baseos/appstream sources,
  with package-signature and TLS checking enabled. No new repository or signing key
  source is configured by this application. DNF may import the configured Rocky key.
- Installation or updates of required dependencies, the requested exact upstream
  version, and the repository's matching RPM release. The RPM release and dependency
  transaction are resolved by DNF at execution time, not frozen at preparation time.
- Packaged configuration, service enablement at boot, and immediate service startup.
  Nginx uses port 80; Tomcat uses port 8080. No firewall or SELinux changes are made.
- Actual Rocky 9, architecture, installed-package, known application-path, systemd,
  disk-space, port-conflict and sudo checks before installation. Existing installations
  or recognized application directories cause refusal. This is not discovery of
  every possible manually installed application or custom data path.

The preview does not inspect the VM. All host preconditions are rechecked when
the approved script runs. If a version is unavailable, DNF fails and the job stops;
there is no fallback to a different version, repository, archive or container.

## Verification and failure

The independent process checks the installed RPM upstream version, boot enablement,
active service, main process, and local HTTP. Nginx also runs `nginx -t` and requires
HTTP 200. Bare Tomcat accepts 200 or 404 because no ROOT application is deployed;
that checks the server response, not the health of a user application.

Jobs retain the existing session/host/digest/authority binding, 10-minute review
expiry, one-use execution, action budget, host lock and audit trail. The approval
endpoint requires an authenticated administrator, CSRF token, correct password,
and the saved digest. Pausing, stopping or replacing authority prevents execution.
Restart never replays a job. Sandbox script limits remain unchanged.

Failure or cancellation can leave installed dependencies, packages or an active
service. Stop is best effort for privileged subprocesses and is not rollback.
Inspect evidence and the VM before preparing another job. No automatic uninstall,
configuration deletion, retry or downgrade is attempted.

## Validation boundary

Automated tests exercise actual MCP dispatch, API approval controls and persisted
jobs with a simulated remote runner, plus installer sequencing and independent
verification with mocked host commands. These are not live installation evidence.
Live Rocky 9 acceptance still requires an enrolled, provisioned disposable VM.

Package selection follows the [DNF command reference](https://dnf.readthedocs.io/en/stable/command_ref.html).
Signature and TLS settings follow the [DNF configuration reference](https://dnf.readthedocs.io/en/latest/conf_ref.html).
