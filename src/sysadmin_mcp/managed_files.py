"""Policy-bound managed-file planning without a generic write primitive."""

from __future__ import annotations

import difflib
import hashlib
import re
from collections.abc import Mapping

from .config import HostConfig, ManagedFilePolicy

MAX_DIFF_LINES = 500
MAX_DIFF_CHARS = 64_000


class ManagedFileDenied(ValueError):
    """Managed-file input failed deterministic policy."""


class ManagedFilePlanner:
    def __init__(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    def replace_hosts(self, hosts: Mapping[str, HostConfig]) -> None:
        self._hosts = dict(hosts)

    def policies(self) -> list[dict[str, object]]:
        return [{"host": host.name, "files": [_policy_view(item) for item in host.managed_files]}
                for host in self._hosts.values()]

    def preview(self, host: str, path_id: str, content: str) -> dict[str, object]:
        policy = self._policy(host, path_id)
        normalized = _content(content, policy.max_bytes)
        _validate(policy.validator, normalized)
        # Phase 18 has no remote reader/writer. The empty baseline and all execution steps
        # are explicitly marked simulated; live adapters must replace this in a later phase.
        diff = list(difflib.unified_diff(
            [], normalized.splitlines(keepends=True),
            fromfile=f"{path_id}:before", tofile=f"{path_id}:proposed", n=3,
        ))
        truncated = len(diff) > MAX_DIFF_LINES or sum(map(len, diff)) > MAX_DIFF_CHARS
        bounded: list[str] = []
        size = 0
        for line in diff[:MAX_DIFF_LINES]:
            if size + len(line) > MAX_DIFF_CHARS:
                break
            bounded.append(line); size += len(line)
        return {
            "path_id": policy.id, "resolved_path": str(policy.path),
            "root": str(policy.root), "owner": policy.owner, "group": policy.group,
            "mode": policy.mode, "validator": policy.validator,
            "content_bytes": len(normalized.encode("utf-8")),
            "content_sha256": hashlib.sha256(normalized.encode()).hexdigest(),
            "diff": "".join(bounded), "diff_truncated": truncated,
            "original_capture": "required_before_apply",
            "symlink_policy": "O_NOFOLLOW and root-contained realpath required",
            "atomic_steps": ["create_same_directory_temp", "write_exact_utf8_bytes",
                             "set_approved_owner_group_mode", "validate_temp_file",
                             "atomic_rename", "fsync_parent_directory"],
            "remote_mutation": False,
        }

    def _policy(self, host: str, path_id: str) -> ManagedFilePolicy:
        try:
            target = self._hosts[host]
        except KeyError as error:
            raise ManagedFileDenied("Unknown or unapproved host") from error
        matches = [item for item in target.managed_files if item.id == path_id]
        if len(matches) != 1:
            raise ManagedFileDenied("Managed file ID is not allowlisted for this host")
        return matches[0]


def _content(value: str, max_bytes: int) -> str:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ManagedFileDenied("Managed content must be valid UTF-8") from error
    if not value.endswith("\n"):
        value += "\n"
        encoded = value.encode("utf-8", errors="strict")
    if not encoded or len(encoded) > max_bytes:
        raise ManagedFileDenied("Managed content is empty or exceeds its policy limit")
    if "\x00" in value or "\r" in value:
        raise ManagedFileDenied("Managed content contains an unsupported control or newline encoding")
    return value


def _validate(validator: str, content: str) -> None:
    if validator == "plain":
        return
    if validator == "nginx":
        if content.count("{") != content.count("}") or re.search(r"(^|\n)\s*(include|load_module)\s+", content):
            raise ManagedFileDenied("Nginx content failed the bounded pre-validator")
        if any(line.strip() and not line.strip().startswith("#") and
               not line.rstrip().endswith((";", "{", "}")) for line in content.splitlines()):
            raise ManagedFileDenied("Nginx directives must end with ';', '{', or '}'")
        return
    if validator == "systemd":
        section = False
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            if re.fullmatch(r"\[[A-Za-z][A-Za-z0-9]+]", stripped):
                section = True
            elif not section or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]+\s*=.*", stripped):
                raise ManagedFileDenied("systemd content failed the bounded pre-validator")
        return
    raise ManagedFileDenied("Unsupported managed-file validator")


def _policy_view(policy: ManagedFilePolicy) -> dict[str, object]:
    return {"id": policy.id, "path": str(policy.path), "validator": policy.validator,
            "owner": policy.owner, "group": policy.group, "mode": policy.mode,
            "max_bytes": policy.max_bytes}
