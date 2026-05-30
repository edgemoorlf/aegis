"""Audit Log: independent, append-only, tamper-evident ground truth.

Every capability issuance, data access, and agent action is recorded here. The
log is the authoritative record: agent memories are derived views, never the
source of truth. Cross-agent discrepancies are resolved against this log.

Tamper-evidence is provided by a hash chain: each entry commits to the previous
entry's hash, so any retroactive edit or deletion breaks the chain and is
detectable by `verify()`. (A Merkle-tree / transparency-log upgrade is noted in
the roadmap for v2.)

From an agent's perspective the log is *write-only*: agents may append, but the
append path is mediated and there is no API to mutate or remove prior entries.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any, Optional

GENESIS_HASH = "0" * 64


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: float
    actor: str           # agent / subject identity
    action: str          # e.g. "capability.issue", "data.read", "data.append"
    target: str          # what was acted on (collection/key, capability id, ...)
    capability_id: Optional[str]
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def payload(self) -> dict[str, Any]:
        """The hashed portion: everything except entry_hash itself."""
        d = asdict(self)
        d.pop("entry_hash")
        return d


def compute_entry_hash(payload: dict[str, Any]) -> str:
    return sha256(_canonical(payload).encode("utf-8")).hexdigest()


class TamperError(RuntimeError):
    """Raised when the audit chain fails integrity verification."""


class AuditLog:
    """Append-only hash-chained log backed by SQLite (insert-only table)."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit (
                    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts            REAL    NOT NULL,
                    actor         TEXT    NOT NULL,
                    action        TEXT    NOT NULL,
                    target        TEXT    NOT NULL,
                    capability_id TEXT,
                    details       TEXT    NOT NULL,
                    prev_hash     TEXT    NOT NULL,
                    entry_hash    TEXT    NOT NULL
                )
                """
            )

    def _last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else GENESIS_HASH

    def append(
        self,
        actor: str,
        action: str,
        target: str,
        *,
        capability_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> AuditEntry:
        details = details or {}
        with self._lock, self._conn:
            prev_hash = self._last_hash()
            seq_row = self._conn.execute("SELECT COALESCE(MAX(seq),0)+1 AS n FROM audit").fetchone()
            seq = seq_row["n"]
            ts = time.time()
            payload = {
                "seq": seq,
                "ts": ts,
                "actor": actor,
                "action": action,
                "target": target,
                "capability_id": capability_id,
                "details": details,
                "prev_hash": prev_hash,
            }
            entry_hash = compute_entry_hash(payload)
            self._conn.execute(
                """INSERT INTO audit
                   (seq, ts, actor, action, target, capability_id, details, prev_hash, entry_hash)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (seq, ts, actor, action, target, capability_id, _canonical(details), prev_hash, entry_hash),
            )
            return AuditEntry(seq, ts, actor, action, target, capability_id, details, prev_hash, entry_hash)

    def verify(self) -> bool:
        """Recompute the chain from genesis. Raises TamperError on mismatch."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM audit ORDER BY seq ASC").fetchall()
        prev = GENESIS_HASH
        for row in rows:
            payload = {
                "seq": row["seq"],
                "ts": row["ts"],
                "actor": row["actor"],
                "action": row["action"],
                "target": row["target"],
                "capability_id": row["capability_id"],
                "details": json.loads(row["details"]),
                "prev_hash": row["prev_hash"],
            }
            if row["prev_hash"] != prev:
                raise TamperError(f"broken link at seq={row['seq']}: prev_hash mismatch")
            expected = compute_entry_hash(payload)
            if expected != row["entry_hash"]:
                raise TamperError(f"tampered entry at seq={row['seq']}: hash mismatch")
            prev = row["entry_hash"]
        return True

    def entries(
        self,
        *,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        target: Optional[str] = None,
    ) -> list[AuditEntry]:
        clauses: list[str] = []
        params: list[Any] = []
        if actor is not None:
            clauses.append("actor=?")
            params.append(actor)
        if action is not None:
            clauses.append("action=?")
            params.append(action)
        if target is not None:
            clauses.append("target=?")
            params.append(target)
        sql = "SELECT * FROM audit"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq ASC"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_entry(r) for r in rows]

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            seq=row["seq"],
            ts=row["ts"],
            actor=row["actor"],
            action=row["action"],
            target=row["target"],
            capability_id=row["capability_id"],
            details=json.loads(row["details"]),
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
