from pathlib import Path
from uuid import uuid4

import pytest

from sysadmin_mcp.chat_store import MAX_CONTENT_CHARS, SQLiteChatStore


def test_chat_messages_round_trip_in_order(tmp_path: Path):
    store = SQLiteChatStore(tmp_path / "assistant.db")
    session_id = str(uuid4())
    store.ensure_session(session_id, "olaf-ubuntu", "gemini")
    store.append(session_id, "user", "Check memory", {"provider": "gemini"})
    store.append(session_id, "assistant", "Memory is normal.")

    messages = store.messages(session_id)

    assert [message["role"] for message in messages] == ["user", "assistant"]
    assert [message["content"] for message in messages] == [
        "Check memory",
        "Memory is normal.",
    ]


@pytest.mark.parametrize("session_id", ["../audit.db", "x' OR 1=1 --", "not-a-uuid"])
def test_malicious_session_ids_are_rejected(tmp_path: Path, session_id: str):
    store = SQLiteChatStore(tmp_path / "assistant.db")
    with pytest.raises(ValueError, match="session id"):
        store.messages(session_id)


def test_oversized_or_invalid_messages_are_rejected(tmp_path: Path):
    store = SQLiteChatStore(tmp_path / "assistant.db")
    session_id = str(uuid4())
    store.ensure_session(session_id, "olaf-ubuntu", "openai")
    with pytest.raises(ValueError, match="exceeds"):
        store.append(session_id, "user", "x" * (MAX_CONTENT_CHARS + 1))
    with pytest.raises(ValueError, match="role"):
        store.append(session_id, "system", "secret")


def test_local_provider_is_saved_in_history(tmp_path: Path):
    store = SQLiteChatStore(tmp_path / "assistant.db")
    session_id = str(uuid4())
    store.ensure_session(session_id, "local-vm", "local")
    store.append(session_id, "user", "Check CPU")

    assert store.sessions()[0]["provider"] == "local"


def test_history_can_be_deleted_individually_or_all_at_once(tmp_path: Path):
    store = SQLiteChatStore(tmp_path / "assistant.db")
    first, second = str(uuid4()), str(uuid4())
    for session_id in (first, second):
        store.ensure_session(session_id, "local-vm", "local")
        store.append(session_id, "user", "Check CPU")

    assert store.delete_session(first) is True
    assert store.delete_session(first) is False
    assert store.messages(first) == []
    assert store.delete_all() == 1
    assert store.sessions() == []


def test_conversation_cannot_move_between_vms(tmp_path: Path):
    store = SQLiteChatStore(tmp_path / "chat.db")
    session = str(uuid4())
    store.ensure_session(session, "vm-a", "openai")
    store.append(session, "user", "Only VM A")
    with pytest.raises(ValueError, match="another VM"):
        store.ensure_session(session, "vm-b", "gemini")
    assert store.sessions()[0]["host"] == "vm-a"
    assert store.sessions()[0]["provider"] == "openai"
    with pytest.raises(ValueError, match="another VM"):
        store.messages(session, host="vm-b")
    assert store.messages(session, host="vm-a")[0]["content"] == "Only VM A"


def test_vm_filter_applies_before_limit_and_supports_multiple_chats(tmp_path: Path):
    store = SQLiteChatStore(tmp_path / "chat.db")
    first, second, other = (str(uuid4()) for _ in range(3))
    for session, host in [(first, "vm-a"), (second, "vm-a"), (other, "vm-b")]:
        store.ensure_session(session, host, "local")
    assert {row["id"] for row in store.sessions(host="vm-a")} == {first, second}
    assert len(store.sessions(limit=1, host="vm-a")) == 1
    assert store.sessions(host="missing") == []
    store.ensure_session(first, "vm-a", "gemini")
    assert store.sessions(host="vm-a")[0]["provider"] == "gemini"


def test_legacy_mixed_history_is_split_without_losing_messages(tmp_path: Path):
    store = SQLiteChatStore(tmp_path / "chat.db")
    session = str(uuid4())
    store.ensure_session(session, "vm-b", "local")
    store.append(session, "user", "A question", {"host": "vm-a"})
    store.append(session, "assistant", "A answer")
    store.append(session, "user", "B question", {"host": "vm-b"})
    store.append(session, "assistant", "B answer")
    migrated = SQLiteChatStore(store.path)
    a = migrated.sessions(host="vm-a")[0]
    assert [row["content"] for row in migrated.messages(a["id"])] == ["A question", "A answer"]
    assert [row["content"] for row in migrated.messages(session)] == ["B question", "B answer"]
    assert len(SQLiteChatStore(store.path).sessions()) == 2
