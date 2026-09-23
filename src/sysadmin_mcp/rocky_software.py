"""Native Rocky 9 software profiles and data-preserving upgrade eligibility.

This module plans operations. It does not grant authority or execute commands.
Version and backup evidence must come from a trusted host adapter, not an LLM.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Literal

Product = Literal["nginx", "tomcat", "kafka", "mysql", "mongodb"]
Operation = Literal["install", "upgrade"]
Deployment = Literal["native", "podman"]
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class SoftwareDenied(ValueError):
    """A software operation cannot proceed with the available evidence."""


@dataclass(frozen=True)
class SoftwareProfile:
    id: Product
    label: str
    service: str
    delivery: str
    data: tuple[str, ...]
    configuration: tuple[str, ...]
    health_checks: tuple[str, ...]
    prerequisites: tuple[str, ...]
    upgrade_notes: str


PROFILES = {
    "nginx": SoftwareProfile(
        "nginx", "Nginx", "nginx.service", "approved_rpm_repository",
        ("/usr/share/nginx/html",), ("/etc/nginx",),
        ("nginx_syntax", "systemd_active", "http_response"), (),
        "Keep virtual hosts, certificates, custom modules and document roots.",
    ),
    "tomcat": SoftwareProfile(
        "tomcat", "Apache Tomcat", "tomcat.service", "approved_rpm_repository",
        ("CATALINA_BASE/webapps",), ("CATALINA_BASE/conf",),
        ("java_compatibility", "tomcat_config", "systemd_active", "application_http"),
        ("java",),
        "Preserve CATALINA_BASE; javax-to-jakarta migration is not an unattended upgrade.",
    ),
    "kafka": SoftwareProfile(
        "kafka", "Apache Kafka", "kafka.service", "verified_apache_archive",
        ("configured_log_dirs", "configured_metadata_log_dir"),
        ("server.properties", "cluster_id", "node_id"),
        ("java_compatibility", "kraft_quorum", "broker_api", "existing_topics"),
        ("java",),
        "Never format existing storage or change cluster IDs; ZooKeeper migration needs a separate plan.",
    ),
    "mysql": SoftwareProfile(
        "mysql", "MySQL", "mysqld.service", "approved_mysql_rpm_repository",
        ("configured_datadir", "configured_external_tablespaces"),
        ("/etc/my.cnf", "/etc/my.cnf.d"),
        ("mysql_upgrade_compatibility", "authenticated_query", "existing_databases"), (),
        "Do not substitute MariaDB, initialize an existing datadir, or downgrade upgraded data files.",
    ),
    "mongodb": SoftwareProfile(
        "mongodb", "MongoDB", "mongod.service", "approved_mongodb_rpm_repository",
        ("configured_storage_dbPath",), ("/etc/mongod.conf",),
        ("feature_compatibility_version", "authenticated_ping", "existing_databases"), (),
        "Preserve dbPath and FCV; replica sets and sharded deployments need topology-specific plans.",
    ),
}


def catalog() -> list[dict[str, object]]:
    return [{**asdict(profile), "platform": "rocky:9", "operations": ["install", "upgrade"],
             "deployment_modes": ["native", "podman"],
             "upgrade_policy": "same_major_minor_only", "live_execution": profile.id in {"nginx", "tomcat"},
             "executable_operations": ["install"] if profile.id in {"nginx", "tomcat"} else [],
             "executable_deployments": ["native"] if profile.id in {"nginx", "tomcat"} else [],
             "approval_required": True}
            for profile in PROFILES.values()]


def version_parts(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or len(value) > 32 or not VERSION.fullmatch(value):
        raise SoftwareDenied("Use an exact upstream version, for example 8.0.12; latest is not a version")
    return tuple(int(part) for part in value.split("."))


def validate_upgrade(current: str, target: str) -> None:
    before, after = version_parts(current), version_parts(target)
    if after <= before:
        raise SoftwareDenied("Upgrade target must be newer than the installed version")
    if before[:2] != after[:2]:
        raise SoftwareDenied("Cross-release upgrade requires a separately reviewed migration plan")


def plan(product: str, operation: str, target_version: str,
         deployment: str = "native") -> dict[str, object]:
    if product not in PROFILES or operation not in {"install", "upgrade"}:
        raise SoftwareDenied("Unsupported software or operation")
    if deployment not in {"native", "podman"}:
        raise SoftwareDenied("Unsupported deployment mode")
    version_parts(target_version)
    profile = PROFILES[product]
    steps = [
        "verify_rocky9_and_architecture", "verify_host_identity_and_authority",
        "inspect_installed_version_and_topology", "resolve_actual_data_and_config_paths",
        "verify_approved_source_and_exact_artifact", "check_disk_memory_and_dependencies",
    ]
    if deployment == "podman":
        steps += ["verify_podman_and_quadlet", "verify_image_digest_and_vendor",
                  "verify_persistent_volume_mapping_and_selinux_labels",
                  "preserve_environment_secrets_and_existing_image_digest"]
    if operation == "upgrade":
        steps += ["reject_unsupported_version_jump", "run_vendor_compatibility_checks",
                  "capture_pre_upgrade_application_inventory", "quiesce_writes_and_stop_service",
                  "capture_consistent_backup_of_all_data_and_configuration",
                  "verify_backup_integrity_and_restore_evidence"]
    else:
        steps += ["refuse_existing_installation_or_nonempty_data_paths"]
    steps += ["recheck_authority_and_plan_hash", "install_exact_approved_version",
              "preserve_existing_configuration" if operation == "upgrade" else "initialize_new_instance",
              "validate_configuration", "start_service", "verify_installed_version",
              *profile.health_checks]
    if operation == "upgrade":
        steps += ["compare_pre_and_post_upgrade_application_inventory"]
    return {
        "product": product, "operation": operation, "target_version": target_version,
        "deployment": deployment,
        "platform": "rocky:9", "steps": steps,
        "preserve_data": True, "preserve_configuration": operation == "upgrade",
        "service_interruption": True, "remote_mutation": False, "executable": False,
        "status": "awaiting_trusted_host_inspection",
        "blocking_requirements": ["enrolled_rocky9_target", "approved_version_and_source",
                                  f"{deployment}_host_adapter", "live_acceptance_evidence"],
        "failure_policy": "stop_and_retain_backup; never automatically downgrade database files",
        "profile": asdict(profile),
    }
