# Phase 2: Linux SSH hardening

Use these steps only on the disposable test host first. Keep an existing root
session open while changing SSH configuration so a mistake does not lock out
the administrator.

The application policy is the first boundary. This phase adds an independent
OS boundary: OpenSSH always sends requests for the dedicated account through
`sysadmin-readonly-command`. The gate accepts only the exact Phase 1 argument
vectors, converts the program name to a fixed absolute path, and calls
`execve`; it never starts a shell.

## 1. Prepare the account and gate

Build a wheel from this repository, copy it to the test host, and install it
as root without runtime dependencies. The forced-command module itself uses
only the Python standard library.

```sh
python -m pip wheel --no-deps .
sudo python3 -m pip install --no-deps ./sysadmin_mcp_assistant-*.whl
sudo useradd --create-home --shell /bin/sh sysadmin-readonly
sudo passwd --lock sysadmin-readonly
sudo chown root:root /usr/local/bin/sysadmin-readonly-command
sudo chmod 0755 /usr/local/bin/sysadmin-readonly-command
```

The login shell remains executable because OpenSSH needs it to launch the
forced command. An interactive shell is nevertheless denied because an empty
`SSH_ORIGINAL_COMMAND` is rejected.

Install the policy file and replace its paths with the exact `allowed_logs`
configured for this host. Never use directories or globs.

```sh
sudo install -o root -g root -m 0644 \
  hardening/sysadmin-readonly-policy.example.toml \
  /etc/sysadmin-readonly-policy.toml
```

Grant only the filesystem reads required by those paths. Prefer file ACLs or a
narrow log-reader group over sudo. Account for log rotation when configuring
ACLs. The account must have no sudoers entry:

```sh
sudo -l -U sysadmin-readonly
sudo getent group sudo wheel adm | grep sysadmin-readonly
```

If the user appears in an administrative group, remove it. Do not grant sudo
for `less`, editors, pagers, shells, or commands which support arbitrary
subcommands. Read-only diagnostics do not require sudo.

Phase 14 remediation is disabled by default (`restart_services = []`). Enabling
it also requires a separately reviewed, least-privilege host authorization for
only the named services. Never grant generic `systemctl`, shell, or unrestricted
sudo access to the diagnostic account.

### Optional Phase 14 service restart helper

Keep `restart_services` empty unless remediation is deliberately enabled. On a
disposable host, add only exact systemd unit names to both the application host
configuration and `/etc/sysadmin-readonly-policy.toml`. Then install and verify
the root-owned helper and narrow sudoers rule:

```sh
sudo chown root:root /usr/local/bin/sysadmin-remediate
sudo chmod 0755 /usr/local/bin/sysadmin-remediate
sudo visudo -cf hardening/sysadmin-remediation.sudoers
sudo install -o root -g root -m 0440 hardening/sysadmin-remediation.sudoers \
  /etc/sudoers.d/sysadmin-remediation
```

The forced-command gate accepts only
`sudo -n /usr/local/bin/sysadmin-remediate restart-service <allowlisted-unit>`.
The helper independently reloads the root-owned policy and maps that typed
request to `/usr/bin/systemctl restart <allowlisted-unit>` using `execve`, never
a shell. The wildcard in sudoers cannot widen authority because extra arguments,
different actions, and non-allowlisted unit names are rejected by both gates.

Before enabling a production unit, test an inert disposable service and rerun
the escape suite. Keep a root console open. Remove the sudoers file and clear
`restart_services` to disable remediation immediately.

## 2. Lock down the SSH key and daemon

Add only the public diagnostic key to
`/home/sysadmin-readonly/.ssh/authorized_keys`, prefixed by `restrict`:

```text
restrict ssh-ed25519 AAAA... diagnostic-client
```

Install the supplied Match block, validate the complete daemon configuration,
then reload it using the service name appropriate for the distribution:

```sh
sudo install -o root -g root -m 0644 hardening/sshd-sysadmin-readonly.conf \
  /etc/ssh/sshd_config.d/60-sysadmin-readonly.conf
sudo sshd -t
sudo systemctl reload ssh
```

`ForceCommand` applies to every key on the account. The key-level `restrict`
option independently disables forwarding, PTY allocation, and agent/X11 use.
Do not enable `PermitUserEnvironment`, because the executed program receives a
hard-coded minimal environment.

## 3. Verify denial and approved reads

From the client, confirm approved commands work:

```sh
ssh sysadmin-readonly@test-host -- who
ssh sysadmin-readonly@test-host -- tail -n 10 /var/log/syslog
```

Then run escape attempts. Every command below must fail with exit status 126,
and `/tmp/phase2-pwned` must not exist afterward:

```sh
ssh sysadmin-readonly@test-host
ssh -t sysadmin-readonly@test-host sh
ssh sysadmin-readonly@test-host -- 'who; touch /tmp/phase2-pwned'
ssh sysadmin-readonly@test-host -- 'who && id'
ssh sysadmin-readonly@test-host -- 'who | tee /tmp/phase2-pwned'
ssh sysadmin-readonly@test-host -- 'who > /tmp/phase2-pwned'
ssh sysadmin-readonly@test-host -- 'tail -n 10 /etc/shadow'
ssh sysadmin-readonly@test-host -- 'systemctl restart ssh'
ssh sysadmin-readonly@test-host -- 'sudo -n /usr/local/bin/sysadmin-remediate restart-service ssh.service'
ssh sysadmin-readonly@test-host -- 'sudo -n /usr/local/bin/sysadmin-remediate restart-service nginx.service extra'
ssh -L 9999:localhost:22 sysadmin-readonly@test-host -- who
```

Also confirm `scp` and SFTP fail: both request commands outside the allowlist.
Record the OpenSSH version, installed file checksums, test commands, exit
statuses, and the result of the final file-existence check for review.

## Operational notes

- Keep the OS policy log list synchronized with each host's application
  `allowed_logs`; the narrower of the two policies wins.
- The fixed executable paths target conventional Linux `/usr/bin` locations.
  Verify them with `command -v` before deployment. Supporting a distribution
  with different paths requires an explicit reviewed code change.
- Rebuild and reinstall the wheel when the gate policy changes, then rerun the
  entire denial checklist.
- Phase 2 is complete only after these checks pass on the disposable host.
