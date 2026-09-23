# Rocky Linux 9 software automation

## Agreed scope

- Nginx, Apache Tomcat, Apache Kafka, MySQL (not MariaDB), and MongoDB.
- Both native systemd services and Podman containers.
- Fresh installation and upgrades are separate operations.
- Upgrades must retain application data and configuration.
- The operator will enroll the Rocky 9 test VM later; no existing VM was selected for mutation.

## Current deliverable

The Software workspace and `/api/software` catalog expose all five products.
`POST /api/software/plan` produces an explicit proposed sequence for an enrolled
development/disposable-lab host. It supports native and Podman deployment modes.
Plans require an exact upstream version and are explicitly non-executable.
The endpoint is administrator-only and protected by the existing authentication
and CSRF middleware. A plan is not evidence that the host runs Rocky 9.

The reusable upgrade eligibility rule only permits strictly newer patch
versions within the same major/minor release. It rejects equal versions,
downgrades, floating versions, and cross-release migrations. That rule must
be applied to versions obtained from trusted host inspection before execution;
the preview endpoint does not accept user-supplied installed-version evidence.

**Available execution:** fresh native Nginx and Tomcat installs through `/api/software/jobs` or MCP `prepare_software_install`. These persist an approval-required host job. The user reviews and reauthenticates in the web UI; installation and verification then run automatically. Both use signed Rocky RPMs from existing baseos/appstream repositories, including Java dependencies for Tomcat. See [approved installation workflow](APPROVED_SOFTWARE_INSTALL.md).

**Still planning-only:** upgrades, Podman deployments, Kafka, MySQL, and MongoDB. Application-specific backup/restore probes and host-enforced recipe policy remain unimplemented. The existing `/api/software/plan` endpoint remains a non-executable planning preview. Native installer behavior has automated tests; live Rocky VM acceptance remains outstanding.

## Data-preservation contract

1. Inspect the real distribution, architecture, installed version, topology,
   service unit, configuration paths, storage paths, external tablespaces,
   symlinks/mounts, and required credentials.
2. Bind the immutable plan to the enrolled host identity and exact approved
   artifact. Repository names, archive locations, image digests, commands,
   paths, and service units are policy-owned rather than model-generated.
3. Verify space for both the replacement and recovery data. Reject unknown
   storage layouts and unreviewed cluster topologies.
4. Capture database/topic/application inventory, quiesce writes, and create a
   consistent backup covering every actual data and configuration path. Verify
   integrity and restoration evidence before replacing binaries or images.
   Merely checking that an archive exists is insufficient.
5. Preserve configuration, credentials, ownership, labels, service identity,
   and storage. Fresh initialization is never part of an upgrade.
6. Verify the installed version, application protocol, and original inventory
   after activation. A successful package command or listening TCP port alone
   is not a successful upgrade.
7. If verification is uncertain, stop and retain recovery evidence. Never
   automatically launch older database binaries against upgraded data files.

Unknown data locations cannot be safely inferred from a generic default path.
The profile catalog includes discovery identifiers such as `configured_datadir`;
these are requirements, not filesystem paths accepted by an executor.

## Native adapters still required

| Product | Installation source | Upgrade-specific work |
| --- | --- | --- |
| Nginx | Approved Rocky/vendor RPM repository, exact package version | Keep virtual hosts, TLS material, modules and custom document roots; run syntax and HTTP checks |
| Tomcat | Verified Apache binary archive and compatible Java | Separate CATALINA_HOME from CATALINA_BASE; preserve deployed apps and configuration; reject automatic javax/jakarta migration |
| Kafka | Verified Apache binary archive and compatible Java | Keep log and metadata directories and cluster/node IDs; never format existing storage; inspect KRaft/ZooKeeper topology and quorum |
| MySQL | Approved Oracle MySQL RPM repository | Inspect datadir and external tablespaces; vendor compatibility checks; preserve authentication/configuration; verify existing databases |
| MongoDB | Approved MongoDB RPM repository | Preserve dbPath and FCV; distinguish standalone/replica set/sharded deployments; verify existing databases |

Minimal VM bootstrap must check SSH, the reviewed privileged helper, Python,
DNF, systemd, free disk/memory, SELinux, and required Java/runtime tools.
Do not disable SELinux or open service ports globally as a shortcut.

## Podman adapters still required

Use approved vendor images pinned by digest and systemd-managed containers.
Store data outside the writable container layer. Inspect actual bind mounts or
named volumes; preserve environment/secrets and SELinux labels. Retain the
previous image digest and deployment definition as recovery evidence. Do not
enable unattended floating-tag auto-update, prune volumes, or substitute an
empty volume when an existing volume cannot be found.

Changing from native to Podman, or back, is a migration rather than an upgrade.
It needs an explicit export/import and verification procedure.

## Acceptance on the later test VM

For each of five products in each deployment mode, test a fresh installation
and a same-release upgrade: 20 primary acceptance scenarios. Seed meaningful
data before upgrading: Nginx content/configuration, a Tomcat application,
Kafka topics/messages/cluster ID, MySQL tables/users, and MongoDB documents/indexes.
Verify these survive unchanged and remain accessible afterward.

Also test unavailable artifacts, checksum mismatch, disk exhaustion, wrong
distribution, absent backups, failed restoration verification, custom storage,
cross-release requests, failed activation, SSH disconnects, backend restart,
expired authority, pause/stop, approval replay, and unexpected cluster topology.
No scenario is marked live-passed until actual VM evidence exists.

## Primary references consulted

- [Tomcat versions and Java requirements](https://tomcat.apache.org/whichversion)
- [Tomcat 10.1 migration guide](https://tomcat.apache.org/migration-10.1.html)
- [Kafka 4.0 upgrade guide](https://kafka.apache.org/40/getting-started/upgrade/)
- [MySQL upgrade guide](https://dev.mysql.com/doc/refman/8.4/en/upgrading.html)
- [MySQL Yum repository guide](https://dev.mysql.com/doc/mysql-yum-repo-quick-guide/en/)
- [MongoDB 8.0 installation on RHEL-compatible systems](https://www.mongodb.com/docs/v8.0/tutorial/install-mongodb-on-red-hat/)
- [Podman Quadlet 4.8 reference](https://docs.podman.io/en/v4.8.0/markdown/podman-systemd.unit.5.html)

These references establish product constraints, not approval of a particular
current release or compatibility of a currently unenrolled VM.
