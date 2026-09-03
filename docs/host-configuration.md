# Phase 6: multi-host configuration

Targets live in `config/hosts.toml`; no target or log path is hardcoded in an
MCP tool. Each host must define:

- a short logical name used by MCP callers;
- hostname and restricted SSH username;
- an absolute local known-hosts file;
- at least one absolute local client-key path;
- one or more exact absolute POSIX log paths;
- CPU and memory warning thresholds greater than 0 and at most 100 percent.

Host names, usernames, paths, thresholds, and control characters are validated
before the configuration is accepted. Missing known-host verification is an
error rather than silently disabling SSH identity checks.

## Management command

Add a host with explicit repeatable key and log options:

```sh
sysadmin-hosts --config config/hosts.toml add web-prod \
  --hostname web-prod.internal \
  --username sysadmin-readonly \
  --known-hosts ~/.ssh/known_hosts \
  --client-key ~/.ssh/sysadmin_readonly \
  --allowed-log /var/log/syslog \
  --allowed-log /var/log/nginx/error.log \
  --cpu-threshold 85 \
  --memory-threshold 90
```

List targets without printing key paths:

```sh
sysadmin-hosts --config config/hosts.toml list
```

Remove an exact logical target:

```sh
sysadmin-hosts --config config/hosts.toml remove web-prod
```

Adding an existing name is denied unless `--replace` is supplied. Every write
validates the complete resulting configuration, writes and fsyncs a temporary
file in the same directory, applies mode `0600`, and atomically replaces the
old file. Restart the MCP server after a configuration change.

## Isolation model

Log allowlists belong to individual hosts. A path approved for `web-prod` is
not approved for `database-prod` unless it is independently listed there.
Tests exercise this boundary directly against the command policy.

The OS forced-command policy from Phase 2 is host-local and must contain the
same or a narrower log set. The narrower of the application and OS policies
wins. Never use globs or directories as log entries.
