"""Local encrypted credential vault; plaintext is never stored in SQLite."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CredentialVault:
    def __init__(self, db_path: Path, key_path: Path) -> None:
        self.db_path, self.key_path = db_path, key_path
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            self._key = key_path.read_bytes()
        else:
            self._key = AESGCM.generate_key(bit_length=256)
            key_path.write_bytes(self._key)
            os.chmod(key_path, 0o600)
        if len(self._key) != 32:
            raise RuntimeError("credential vault key is invalid")
        with sqlite3.connect(db_path) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS host_credentials (
              host TEXT PRIMARY KEY, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL)""")

    def set(self, host: str, password: str) -> None:
        nonce = os.urandom(12)
        encrypted = AESGCM(self._key).encrypt(nonce, password.encode(), host.encode())
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT OR REPLACE INTO host_credentials VALUES (?,?,?)", (host, nonce, encrypted))

    def get(self, host: str) -> str | None:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT nonce,ciphertext FROM host_credentials WHERE host=?", (host,)).fetchone()
        return AESGCM(self._key).decrypt(row[0], row[1], host.encode()).decode() if row else None

    def delete(self, host: str) -> None:
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM host_credentials WHERE host=?", (host,))
