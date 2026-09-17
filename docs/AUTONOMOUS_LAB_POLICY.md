# Autonomous Lab Policy

Autonomous Lab is bounded unattended execution, not unrestricted root access.
It is intended for personal development VMs and disposable test VMs.

## Operator-controlled envelope

Before execution, an Administrator must reauthenticate and choose:

- exact enrolled VM names;
- permitted versioned recipe IDs;
- capabilities such as packages, managed files, services, and backups;
- maximum action count and concurrency;
- session expiry and maintenance window;
- allowed service-impact level.

The server hashes this envelope. The LLM cannot widen it, renew it, add a host,
change VM classification, or create a privileged operation.

## Host eligibility

Only `development` and `disposable_lab` hosts are eligible. `production` and
`staging` are denied. Classification must be checked independently by the web
API, authority policy, transport identity, and root-owned host helper. A mismatch
or missing classification fails closed and resets the session to Observe.

## Execution model

The first live recipe will be `nginx_install_configure`. It accepts only opaque
policy IDs and bounded content fields, then performs this fixed sequence:

1. Inspect current package, files, service, ports, and health.
2. Capture and verify recovery snapshots.
3. Simulate the exact package transaction and reject removals or surprises.
4. Install the allowlisted package/version through a fixed root helper.
5. Atomically replace named managed files beneath reviewed roots.
6. Run the fixed Nginx syntax validator.
7. Enable and activate the allowlisted systemd unit.
8. Verify process state, ports, bounded logs, and HTTP health.
9. Accept verified state or invoke the predefined rollback.

No recipe accepts raw shell, executable paths, repository/key changes, arbitrary
filesystem paths, service-unit names, or unbounded output.

## Automatic stop conditions

Automation pauses or stops when any of these occur:

- plan or diff hash changes;
- backup integrity or freshness fails;
- canary, syntax validation, service health, or rollback verification fails;
- package removals, dependency surprises, unavailable prior versions, or an
  ambiguous rollback condition appear;
- host lock, timeout, action budget, failure budget, or circuit limit is reached;
- audit persistence, recovery persistence, SSH identity, or helper policy fails;
- the backend restarts, authority expires, an operator pauses/stops, or a host is
  reclassified.

## Initial release gate

Live execution remains disabled until Phase 22 produces disposable-VM evidence
for process kills, disconnects, symlink races, helper policy rejection, recovery,
and production fail-closed checks with named operator sign-off.
