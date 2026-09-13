"""Configuration models and loading for approved target hosts.

Host configuration is deliberately separate from tool code. Connection details
and per-host log-path allowlists must be reviewable without editing the
executor's command policy.
"""

import json
import os
import re
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

HOST_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
USERNAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,31}\Z")
SERVICE_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}(?:\.service)?\Z")
BACKUP_JOB_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
MANAGED_FILE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
ENVIRONMENTS = frozenset({"production", "staging", "development", "disposable_lab"})
FILE_VALIDATORS = frozenset({"plain", "nginx", "systemd"})
FILE_MODES = frozenset({"0600", "0640", "0644"})
PACKAGE_MANAGERS = frozenset({"apt"})
SERVICE_ACTIONS = frozenset({
    "enable_service", "disable_service", "reload_service", "restart_service"
})
FORBIDDEN_FILE_ROOTS = ("/proc", "/sys", "/dev", "/run")


class ConfigError(ValueError):
    """Host configuration is missing, malformed, or outside policy."""


@dataclass(frozen=True)
class ResourceThresholds:
    """Per-host percentages used by presentation anomaly checks."""

    cpu_percent: float = 90.0
    memory_percent: float = 90.0


@dataclass(frozen=True)
class ManagedFilePolicy:
    """Reviewed mapping from an opaque ID to one exact managed file."""

    id: str
    root: PurePosixPath
    relative_path: PurePosixPath
    validator: str = "plain"
    owner: str = "root"
    group: str = "root"
    mode: str = "0644"
    max_bytes: int = 32_000

    @property
    def path(self) -> PurePosixPath:
        return self.root / self.relative_path


@dataclass(frozen=True)
class PackagePolicy:
    id: str
    name: str
    allowed_versions: tuple[str, ...]
    dependencies: tuple[str, ...] = ()
    dependent_services: tuple[str, ...] = ()
    download_bytes: int = 0
    disk_bytes: int = 0
    reboot_required: bool = False
    held: bool = False


@dataclass(frozen=True)
class ServicePolicy:
    id: str
    unit: str
    actions: tuple[str, ...]
    config_path_id: str | None = None
    listen_ports: tuple[int, ...] = ()
    health_path: str | None = None
    log_path: PurePosixPath | None = None
    max_log_lines: int = 100
    material_restart: bool = True


@dataclass(frozen=True)
class HostConfig:
    """A single SSH target and the log files it permits reading."""

    name: str
    hostname: str
    username: str
    known_hosts: str | None
    client_keys: tuple[Path, ...]
    allowed_logs: frozenset[PurePosixPath]
    port: int = 22
    password_env: str | None = None
    thresholds: ResourceThresholds = ResourceThresholds()
    restart_services: frozenset[str] = frozenset()
    backup_jobs: frozenset[str] = frozenset()
    managed_files: tuple[ManagedFilePolicy, ...] = ()
    package_manager: str = "apt"
    packages: tuple[PackagePolicy, ...] = ()
    services: tuple[ServicePolicy, ...] = ()
    environment: str = "production"


def load_hosts(path: Path) -> dict[str, HostConfig]:
    """Load explicitly named targets from a TOML file."""
    try:
        with path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigError(f"Could not load host configuration: {path}") from error

    hosts: dict[str, HostConfig] = {}
    raw_hosts = data.get("hosts", {})
    if not isinstance(raw_hosts, dict):
        raise ConfigError("The hosts configuration must be a TOML table")
    for name, values in raw_hosts.items():
        if not isinstance(values, dict):
            raise ConfigError(f"Host {name!r} must be a TOML table")
        try:
            thresholds = values.get("thresholds", {})
            if not isinstance(thresholds, dict):
                raise TypeError("thresholds must be a table")
            host = HostConfig(
                name=name,
                hostname=values["hostname"],
                username=values["username"],
                known_hosts=str(Path(values["known_hosts"]).expanduser()),
                client_keys=tuple(
                    Path(item).expanduser()
                    for item in _string_list(
                        values["client_keys"], "client_keys", allow_empty=True
                    )
                ),
                password_env=values.get("password_env"),
                port=values.get("port", 22),
                allowed_logs=frozenset(
                    PurePosixPath(item)
                    for item in _string_list(values["allowed_logs"], "allowed_logs")
                ),
                thresholds=ResourceThresholds(
                    cpu_percent=thresholds.get("cpu_percent", 90.0),
                    memory_percent=thresholds.get("memory_percent", 90.0),
                ),
                restart_services=frozenset(
                    _string_list(values.get("restart_services", []), "restart_services", allow_empty=True)
                ),
                backup_jobs=frozenset(
                    _string_list(values.get("backup_jobs", []), "backup_jobs", allow_empty=True)
                ),
                managed_files=_managed_files(values.get("managed_files", [])),
                package_manager=values.get("package_manager", "apt"),
                packages=_packages(values.get("packages", [])),
                services=_services(values.get("services", [])),
                environment=values.get("environment", "production"),
            )
        except (KeyError, TypeError) as error:
            raise ConfigError(f"Host {name!r} is missing a required setting") from error
        validate_host(host)
        hosts[name] = host
    return hosts


def validate_host(host: HostConfig) -> None:
    """Validate one complete target without performing network or filesystem I/O."""
    if not HOST_NAME_PATTERN.fullmatch(host.name):
        raise ConfigError(f"Host name {host.name!r} is invalid")
    if (
        not isinstance(host.hostname, str)
        or not 1 <= len(host.hostname) <= 253
        or any(character in host.hostname for character in ("\x00", "\n", "\r"))
    ):
        raise ConfigError(f"Host {host.name!r} has an invalid hostname")
    if not isinstance(host.username, str) or not USERNAME_PATTERN.fullmatch(host.username):
        raise ConfigError(f"Host {host.name!r} has an invalid username")
    if isinstance(host.port, bool) or not isinstance(host.port, int) or not 1 <= host.port <= 65535:
        raise ConfigError(f"Host {host.name!r} has an invalid SSH port")
    if (
        not isinstance(host.known_hosts, str)
        or not host.known_hosts.strip()
        or any(character in host.known_hosts for character in ("\x00", "\n", "\r"))
        or not Path(host.known_hosts).is_absolute()
    ):
        raise ConfigError(f"Host {host.name!r} must configure known_hosts")
    if host.client_keys and not all(
        isinstance(key, Path)
        and key.is_absolute()
        and not any(character in str(key) for character in ("\x00", "\n", "\r"))
        for key in host.client_keys
    ):
        raise ConfigError(f"Host {host.name!r} has an invalid client key")
    if host.password_env is not None and (
        not isinstance(host.password_env, str)
        or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", host.password_env)
    ):
        raise ConfigError(f"Host {host.name!r} has an invalid password_env")
    if not host.client_keys and not host.password_env:
        raise ConfigError(f"Host {host.name!r} must configure a client key or password_env")
    if not host.allowed_logs or not all(_safe_log_path(log) for log in host.allowed_logs):
        raise ConfigError(f"Host {host.name!r} has an unsafe allowed log path")
    for label, value in (
        ("cpu_percent", host.thresholds.cpu_percent),
        ("memory_percent", host.thresholds.memory_percent),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 100:
            raise ConfigError(f"Host {host.name!r} threshold {label} must be > 0 and <= 100")
    if not all(isinstance(service, str) and SERVICE_NAME_PATTERN.fullmatch(service)
               for service in host.restart_services):
        raise ConfigError(f"Host {host.name!r} has an invalid restart service")
    if not all(isinstance(job, str) and BACKUP_JOB_PATTERN.fullmatch(job)
               for job in host.backup_jobs):
        raise ConfigError(f"Host {host.name!r} has an invalid backup job")
    if host.environment not in ENVIRONMENTS:
        raise ConfigError(f"Host {host.name!r} has an invalid environment classification")
    ids = [policy.id for policy in host.managed_files]
    if len(ids) != len(set(ids)) or not all(_valid_managed_file(item) for item in host.managed_files):
        raise ConfigError(f"Host {host.name!r} has an invalid managed file policy")
    package_ids = [policy.id for policy in host.packages]
    if (host.package_manager not in PACKAGE_MANAGERS or len(package_ids) != len(set(package_ids))
            or not all(_valid_package(item) for item in host.packages)):
        raise ConfigError(f"Host {host.name!r} has an invalid package policy")
    service_ids = [policy.id for policy in host.services]
    if len(service_ids) != len(set(service_ids)) or not all(
        _valid_service(item, host) for item in host.services
    ):
        raise ConfigError(f"Host {host.name!r} has an invalid service policy")


def save_hosts(path: Path, hosts: dict[str, HostConfig]) -> None:
    """Atomically replace the configuration with validated, deterministically sorted TOML."""
    for name, host in hosts.items():
        if name != host.name:
            raise ConfigError("Host mapping key does not match HostConfig.name")
        validate_host(host)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = _serialize_hosts(hosts)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    except OSError as error:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise ConfigError(f"Could not save host configuration: {path}") from error


def _safe_log_path(log: PurePosixPath) -> bool:
    return (
        isinstance(log, PurePosixPath)
        and log.is_absolute()
        and ".." not in log.parts
        and not any(character in str(log) for character in ("\x00", "\n", "\r"))
    )


def _string_list(value: object, setting: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value) or not all(
        isinstance(item, str) for item in value
    ):
        raise ConfigError(f"{setting} must be a non-empty list of strings")
    return value


def _managed_files(value: object) -> tuple[ManagedFilePolicy, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ConfigError("managed_files must be a list of policy tables")
    try:
        return tuple(ManagedFilePolicy(
            id=item["id"], root=PurePosixPath(item["root"]),
            relative_path=PurePosixPath(item["relative_path"]),
            validator=item.get("validator", "plain"), owner=item.get("owner", "root"),
            group=item.get("group", "root"), mode=item.get("mode", "0644"),
            max_bytes=item.get("max_bytes", 32_000),
        ) for item in value)
    except (KeyError, TypeError) as error:
        raise ConfigError("managed_files contains an incomplete policy") from error


def _valid_managed_file(policy: ManagedFilePolicy) -> bool:
    path = policy.path
    return (
        MANAGED_FILE_ID_PATTERN.fullmatch(policy.id) is not None
        and policy.root.is_absolute() and not policy.relative_path.is_absolute()
        and str(policy.relative_path) not in {"", "."}
        and ".." not in policy.root.parts and ".." not in policy.relative_path.parts
        and not any(str(path) == root or str(path).startswith(root + "/")
                    for root in FORBIDDEN_FILE_ROOTS)
        and policy.validator in FILE_VALIDATORS
        and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", policy.owner) is not None
        and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", policy.group) is not None
        and policy.mode in FILE_MODES
        and isinstance(policy.max_bytes, int) and not isinstance(policy.max_bytes, bool)
        and 1 <= policy.max_bytes <= 64_000
    )


def _packages(value: object) -> tuple[PackagePolicy, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ConfigError("packages must be a list of policy tables")
    try:
        return tuple(PackagePolicy(
            id=item["id"], name=item["name"], allowed_versions=tuple(item["allowed_versions"]),
            dependencies=tuple(item.get("dependencies", [])),
            dependent_services=tuple(item.get("dependent_services", [])),
            download_bytes=item.get("download_bytes", 0), disk_bytes=item.get("disk_bytes", 0),
            reboot_required=item.get("reboot_required", False), held=item.get("held", False),
        ) for item in value)
    except (KeyError, TypeError) as error:
        raise ConfigError("packages contains an incomplete policy") from error


def _valid_package(policy: PackagePolicy) -> bool:
    token = r"[a-z0-9][a-z0-9+.-]{0,127}"
    version = r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}"
    return (
        MANAGED_FILE_ID_PATTERN.fullmatch(policy.id) is not None
        and re.fullmatch(token, policy.name) is not None
        and 1 <= len(policy.allowed_versions) <= 20
        and all(re.fullmatch(version, item) for item in policy.allowed_versions)
        and len(policy.dependencies) <= 100 and all(re.fullmatch(token, item) for item in policy.dependencies)
        and len(policy.dependent_services) <= 20
        and all(SERVICE_NAME_PATTERN.fullmatch(item) for item in policy.dependent_services)
        and isinstance(policy.download_bytes, int) and not isinstance(policy.download_bytes, bool)
        and 0 <= policy.download_bytes <= 2_000_000_000
        and isinstance(policy.disk_bytes, int) and not isinstance(policy.disk_bytes, bool)
        and 0 <= policy.disk_bytes <= 4_000_000_000
        and isinstance(policy.reboot_required, bool) and isinstance(policy.held, bool)
    )


def _services(value: object) -> tuple[ServicePolicy, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ConfigError("services must be a list of policy tables")
    try:
        return tuple(ServicePolicy(
            id=item["id"], unit=item["unit"], actions=tuple(item["actions"]),
            config_path_id=item.get("config_path_id"),
            listen_ports=tuple(item.get("listen_ports", [])),
            health_path=item.get("health_path"),
            log_path=PurePosixPath(item["log_path"]) if item.get("log_path") else None,
            max_log_lines=item.get("max_log_lines", 100),
            material_restart=item.get("material_restart", True),
        ) for item in value)
    except (KeyError, TypeError) as error:
        raise ConfigError("services contains an incomplete policy") from error


def _valid_service(policy: ServicePolicy, host: HostConfig) -> bool:
    file_ids = {item.id for item in host.managed_files}
    return (
        MANAGED_FILE_ID_PATTERN.fullmatch(policy.id) is not None
        and SERVICE_NAME_PATTERN.fullmatch(policy.unit) is not None
        and 1 <= len(policy.actions) <= 4 and set(policy.actions) <= SERVICE_ACTIONS
        and (policy.config_path_id is None or policy.config_path_id in file_ids)
        and len(policy.listen_ports) <= 20
        and all(isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535
                for port in policy.listen_ports)
        and (policy.health_path is None or re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}", policy.health_path))
        and (policy.log_path is None or policy.log_path in host.allowed_logs)
        and isinstance(policy.max_log_lines, int) and not isinstance(policy.max_log_lines, bool)
        and 1 <= policy.max_log_lines <= 200 and isinstance(policy.material_restart, bool)
    )


def _serialize_hosts(hosts: dict[str, HostConfig]) -> str:
    if not hosts:
        return "[hosts]\n"
    sections: list[str] = [
        "# Managed by sysadmin-hosts. Review changes before deploying."
    ]
    for name in sorted(hosts):
        host = hosts[name]
        table_name = json.dumps(name)
        sections.extend(
            (
                "",
                f"[hosts.{table_name}]",
                f"hostname = {json.dumps(host.hostname)}",
                f"port = {host.port}",
                f"username = {json.dumps(host.username)}",
                f"environment = {json.dumps(host.environment)}",
                f"known_hosts = {json.dumps(str(host.known_hosts))}",
                "client_keys = " + _toml_array(str(key) for key in host.client_keys),
                *( [f"password_env = {json.dumps(host.password_env)}"] if host.password_env else [] ),
                "allowed_logs = " + _toml_array(str(log) for log in sorted(host.allowed_logs)),
                "restart_services = " + _toml_array(sorted(host.restart_services)),
                "backup_jobs = " + _toml_array(sorted(host.backup_jobs)),
                "managed_files = " + _toml_managed_files(host.managed_files),
                f"package_manager = {json.dumps(host.package_manager)}",
                "packages = " + _toml_packages(host.packages),
                "services = " + _toml_services(host.services),
                "",
                f"[hosts.{table_name}.thresholds]",
                f"cpu_percent = {float(host.thresholds.cpu_percent)}",
                f"memory_percent = {float(host.thresholds.memory_percent)}",
            )
        )
    return "\n".join(sections) + "\n"


def _toml_array(values) -> str:
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


def _toml_managed_files(values: tuple[ManagedFilePolicy, ...]) -> str:
    rows = []
    for item in values:
        rows.append("{ " + ", ".join((
            f"id = {json.dumps(item.id)}", f"root = {json.dumps(str(item.root))}",
            f"relative_path = {json.dumps(str(item.relative_path))}",
            f"validator = {json.dumps(item.validator)}", f"owner = {json.dumps(item.owner)}",
            f"group = {json.dumps(item.group)}", f"mode = {json.dumps(item.mode)}",
            f"max_bytes = {item.max_bytes}",
        )) + " }")
    return "[" + ", ".join(rows) + "]"


def _toml_packages(values: tuple[PackagePolicy, ...]) -> str:
    rows = []
    for item in values:
        rows.append("{ " + ", ".join((
            f"id = {json.dumps(item.id)}", f"name = {json.dumps(item.name)}",
            "allowed_versions = " + _toml_array(item.allowed_versions),
            "dependencies = " + _toml_array(item.dependencies),
            "dependent_services = " + _toml_array(item.dependent_services),
            f"download_bytes = {item.download_bytes}", f"disk_bytes = {item.disk_bytes}",
            f"reboot_required = {str(item.reboot_required).lower()}",
            f"held = {str(item.held).lower()}",
        )) + " }")
    return "[" + ", ".join(rows) + "]"


def _toml_services(values: tuple[ServicePolicy, ...]) -> str:
    rows = []
    for item in values:
        fields = [
            f"id = {json.dumps(item.id)}", f"unit = {json.dumps(item.unit)}",
            "actions = " + _toml_array(item.actions),
            "listen_ports = [" + ", ".join(str(port) for port in item.listen_ports) + "]",
            f"max_log_lines = {item.max_log_lines}",
            f"material_restart = {str(item.material_restart).lower()}",
        ]
        if item.config_path_id: fields.append(f"config_path_id = {json.dumps(item.config_path_id)}")
        if item.health_path: fields.append(f"health_path = {json.dumps(item.health_path)}")
        if item.log_path: fields.append(f"log_path = {json.dumps(str(item.log_path))}")
        rows.append("{ " + ", ".join(fields) + " }")
    return "[" + ", ".join(rows) + "]"
