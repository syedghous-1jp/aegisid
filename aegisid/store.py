"""Persistent state (SQLite): batches, products, used nonces and the audit log.

Using a database instead of Python sets and lists gives AegisID:

* state that survives restarts and is shared by several worker processes;
* an *atomic* "burn nonce + append audit record" step, so two simultaneous
  scans of the same token can never both succeed.

``Store()`` defaults to an in-memory database (tests, demos).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Callable, Optional

GENESIS = "GENESIS"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta      (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS batches   (batch_id TEXT PRIMARY KEY, region TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products  (pid TEXT PRIMARY KEY, batch_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS used_nonces (nonce TEXT PRIMARY KEY, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS log (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    record TEXT NOT NULL,
    hash   TEXT NOT NULL,
    sig    TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False,
                                   isolation_level=None, timeout=30)
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)

    # ---- small helpers -------------------------------------------------
    def _one(self, sql: str, args: tuple = ()):
        with self._lock:
            row = self._db.execute(sql, args).fetchone()
        return row[0] if row else None

    # ---- metadata (signing-key binding) ---------------------------------
    def get_meta(self, key: str) -> Optional[str]:
        return self._one("SELECT v FROM meta WHERE k=?", (key,))

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)", (key, value))

    # ---- batches and products -------------------------------------------
    def add_batch(self, batch_id: str, region: str) -> None:
        with self._lock:
            existing = self.batch_region(batch_id)
            if existing is not None:
                if existing != region:
                    raise ValueError("batch already registered with a different region")
                return
            self._db.execute("INSERT INTO batches(batch_id, region) VALUES (?, ?)",
                             (batch_id, region))

    def batch_region(self, batch_id: str) -> Optional[str]:
        return self._one("SELECT region FROM batches WHERE batch_id=?", (batch_id,))

    def add_product(self, pid: str, batch_id: str) -> None:
        with self._lock:
            self._db.execute("INSERT INTO products(pid, batch_id) VALUES (?, ?)", (pid, batch_id))

    def product_batch(self, pid: str) -> Optional[str]:
        return self._one("SELECT batch_id FROM products WHERE pid=?", (pid,))

    # ---- nonces + audit log ---------------------------------------------
    def nonce_used(self, nonce: str) -> bool:
        return self._one("SELECT 1 FROM used_nonces WHERE nonce=?", (nonce,)) is not None

    def log_head(self) -> str:
        return self._one("SELECT hash FROM log ORDER BY seq DESC LIMIT 1") or GENESIS

    def log_rows(self) -> list:
        with self._lock:
            cur = self._db.execute("SELECT seq, record, hash, sig FROM log ORDER BY seq")
            return [dict(zip(("seq", "record", "hash", "sig"), r)) for r in cur.fetchall()]

    def log_count(self) -> int:
        return self._one("SELECT COUNT(*) FROM log") or 0

    def commit_scan(self, nonce: str,
                    build: Callable[[str], tuple]) -> Optional[dict]:
        """Atomically burn ``nonce`` and append one audit record.

        ``build(prev_hash)`` must return ``(record_text, hash, signature)``.
        Returns ``{"hash": ...}``, or ``None`` if the nonce was already used.
        Everything happens in one ``BEGIN IMMEDIATE`` transaction, which also
        serialises concurrent writers across worker processes.
        """
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = self._db.execute(
                    "INSERT OR IGNORE INTO used_nonces(nonce, ts) VALUES (?, ?)",
                    (nonce, time.time()))
                if cur.rowcount != 1:
                    self._db.execute("ROLLBACK")
                    return None
                text, digest, sig = build(self.log_head())
                self._db.execute("INSERT INTO log(record, hash, sig) VALUES (?, ?, ?)",
                                 (text, digest, sig))
                self._db.execute("COMMIT")
                return {"hash": digest}
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._db.close()
