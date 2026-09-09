import sqlite3
from pathlib import Path

from sysadmin_mcp.credential_vault import CredentialVault


def test_password_is_encrypted_at_rest_and_deletable(tmp_path: Path):
    db, key = tmp_path / "vault.db", tmp_path / "vault.key"
    vault = CredentialVault(db, key)
    vault.set("vm-1", "correct horse battery staple")
    assert vault.get("vm-1") == "correct horse battery staple"
    with sqlite3.connect(db) as connection:
        row = connection.execute("SELECT nonce,ciphertext FROM host_credentials").fetchone()
    assert b"correct horse" not in row[1]
    assert len(row[0]) == 12 and key.read_bytes() != row[1]
    vault.delete("vm-1")
    assert vault.get("vm-1") is None
