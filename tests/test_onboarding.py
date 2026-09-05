from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from sysadmin_mcp.config import load_hosts
from sysadmin_mcp.onboarding import HostOnboardingService, VMOnboardingRequest


class FakeKey:
    def __init__(self, material: bytes = b"ssh-ed25519 AAAATEST") -> None:
        self.material = material

    def export_public_key(self, format_name: str) -> bytes:
        assert format_name == "openssh"
        return self.material

    def get_algorithm(self) -> str:
        return "ssh-ed25519"

    def get_fingerprint(self, hash_name: str) -> str:
        assert hash_name == "sha256"
        return "SHA256:test-fingerprint"


def request() -> VMOnboardingRequest:
    return VMOnboardingRequest(
        name="web-02",
        hostname="192.168.0.110",
        username="sentinel",
        password_env="SSH_PASSWORD_WEB_02",
        allowed_logs=["/var/log/syslog"],
    )


@pytest.mark.asyncio
async def test_trust_requires_same_key_twice_and_saves_atomically(tmp_path: Path):
    config = tmp_path / "hosts.toml"
    known_hosts = tmp_path / "known_hosts"
    service = HostOnboardingService(config, known_hosts)
    with patch(
        "sysadmin_mcp.onboarding.asyncssh.get_server_host_key",
        AsyncMock(side_effect=[FakeKey(), FakeKey()]),
    ):
        discovered = await service.discover(request())
        host = await service.decide(discovered["token"], True)

    assert host is not None
    assert load_hosts(config)["web-02"].port == 22
    assert known_hosts.read_text().startswith("192.168.0.110 ssh-ed25519 ")


@pytest.mark.asyncio
async def test_no_decision_does_not_write_files(tmp_path: Path):
    service = HostOnboardingService(tmp_path / "hosts.toml", tmp_path / "known_hosts")
    with patch(
        "sysadmin_mcp.onboarding.asyncssh.get_server_host_key",
        AsyncMock(return_value=FakeKey()),
    ):
        discovered = await service.discover(request())
        assert await service.decide(discovered["token"], False) is None
    assert not (tmp_path / "hosts.toml").exists()
    assert not (tmp_path / "known_hosts").exists()


@pytest.mark.asyncio
async def test_changed_key_is_rejected_without_writes(tmp_path: Path):
    service = HostOnboardingService(tmp_path / "hosts.toml", tmp_path / "known_hosts")
    with patch(
        "sysadmin_mcp.onboarding.asyncssh.get_server_host_key",
        AsyncMock(side_effect=[FakeKey(), FakeKey(b"ssh-ed25519 DIFFERENT")]),
    ):
        discovered = await service.discover(request())
        with pytest.raises(ValueError, match="changed"):
            await service.decide(discovered["token"], True)
    assert not (tmp_path / "known_hosts").exists()


@pytest.mark.asyncio
async def test_malicious_log_path_is_rejected_before_network(tmp_path: Path):
    service = HostOnboardingService(tmp_path / "hosts.toml", tmp_path / "known_hosts")
    malicious = request().model_copy(update={"allowed_logs": ["../../etc/shadow"]})
    network = AsyncMock()
    with (
        patch("sysadmin_mcp.onboarding.asyncssh.get_server_host_key", network),
        pytest.raises(ValueError, match="unsafe allowed log"),
    ):
        await service.discover(malicious)
    network.assert_not_awaited()
