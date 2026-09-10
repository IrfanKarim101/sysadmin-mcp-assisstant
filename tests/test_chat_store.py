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
