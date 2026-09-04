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
