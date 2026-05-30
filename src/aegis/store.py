"""Immutable Store: append-only, versioned, time-travel reads.

The data plane of Aegis. The central invariant is *never delete*: every write
creates a new version, nothing is ever overwritten or removed. "Deletion" is a
logical tombstone (a new version marked deleted), so history remains complete
and auditable.

Compute is assumed untrusted and transient; this layer is where data robustness
and provenance live.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterator, Optional


def _canonical(value: Any) -> str:
    """Deterministic JSON encoding so content hashes are stable."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(value: Any) -> str:
    return sha256(_canonical(value).encode("utf-8")).hexdigest()


class TombstoneError(KeyError):
    """Raised when reading a key whose latest version is a tombstone."""


@dataclass(frozen=True)
class Version:
    """A single immutable version of a record."""

    collection: str
    key: str
    version: int
    value: Any
    content_hash: str
    author: str
    ts: float
    deleted: bool

    @property
    def is_tombstone(self) -> bool:
        return self.deleted


class ImmutableStore:
    """Append-only versioned store backed by SQLite.

    Reads are time-travelable by version number or timestamp. The underlying
    table is insert-only: no code path issues UPDATE or DELETE.
    """

    def __init__(self, path: str = ":memory:") -> None:
        # check_same_thread=False + a lock keeps the reference impl simple while
        # remaining safe for the single-writer model we assume in v1.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS records (
                    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
                    collection   TEXT    NOT NULL,
                    key          TEXT    NOT NULL,
                    version      INTEGER NOT NULL,
                    value        TEXT    NOT NULL,
                    content_hash TEXT    NOT NULL,
                    author       TEXT    NOT NULL,
                    ts           REAL    NOT NULL,
                    deleted      INTEGER NOT NULL DEFAULT 0,
                    UNIQUE (collection, key, version)
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ck ON records (collection, key, version)"
            )

    # -- writes --------------------------------------------------------------

    def append(self, collection: str, key: str, value: Any, author: str) -> Version:
        """Write a new version of (collection, key). Never overwrites."""
        return self._append(collection, key, value, author, deleted=False)

    def tombstone(self, collection: str, key: str, author: str) -> Version:
        """Logically delete a key by appending a tombstone version.

        The prior versions remain readable via time-travel; only the *latest*
        view reports the key as deleted. This preserves the never-delete rule.
        """
        return self._append(collection, key, None, author, deleted=True)

    def _append(
        self, collection: str, key: str, value: Any, author: str, deleted: bool
    ) -> Version:
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT MAX(version) AS v FROM records WHERE collection=? AND key=?",
                (collection, key),
            ).fetchone()
            next_version = (row["v"] or 0) + 1
            ts = time.time()
            chash = content_hash(value)
            self._conn.execute(
                """INSERT INTO records
                   (collection, key, version, value, content_hash, author, ts, deleted)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (collection, key, next_version, _canonical(value), chash, author, ts, int(deleted)),
            )
            return Version(collection, key, next_version, value, chash, author, ts, deleted)

    # -- reads ---------------------------------------------------------------

    def read(
        self,
        collection: str,
        key: str,
        *,
        as_of_version: Optional[int] = None,
        as_of_ts: Optional[float] = None,
    ) -> Version:
        """Read the latest version, or the version as of a point in time.

        Raises KeyError if the key never existed, TombstoneError if the
        resolved version is a tombstone.
        """
        v = self.read_or_none(
            collection, key, as_of_version=as_of_version, as_of_ts=as_of_ts
        )
        if v is None:
            raise KeyError(f"{collection}/{key} not found at requested point")
        if v.is_tombstone:
            raise TombstoneError(f"{collection}/{key} is deleted (v{v.version})")
        return v

    def read_or_none(
        self,
        collection: str,
        key: str,
        *,
        as_of_version: Optional[int] = None,
        as_of_ts: Optional[float] = None,
        include_tombstone: bool = True,
    ) -> Optional[Version]:
        clauses = ["collection=?", "key=?"]
        params: list[Any] = [collection, key]
        if as_of_version is not None:
            clauses.append("version<=?")
            params.append(as_of_version)
        if as_of_ts is not None:
            clauses.append("ts<=?")
            params.append(as_of_ts)
        sql = (
            "SELECT * FROM records WHERE "
            + " AND ".join(clauses)
            + " ORDER BY version DESC LIMIT 1"
        )
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        if row is None:
            return None
        v = self._row_to_version(row)
        if v.is_tombstone and not include_tombstone:
            return None
        return v

    def history(self, collection: str, key: str) -> list[Version]:
        """Full version history for a key, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM records WHERE collection=? AND key=? ORDER BY version ASC",
                (collection, key),
            ).fetchall()
        return [self._row_to_version(r) for r in rows]

    def keys(self, collection: str, *, include_deleted: bool = False) -> list[str]:
        """Distinct keys whose latest version is live (or all, if requested)."""
        out: list[str] = []
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT key FROM records WHERE collection=?", (collection,)
            ).fetchall()
        for r in rows:
            v = self.read_or_none(collection, r["key"])
            if v is None:
                continue
            if v.is_tombstone and not include_deleted:
                continue
            out.append(r["key"])
        return sorted(out)

    def scan(self, collection: str) -> Iterator[Version]:
        """Iterate every version ever written to a collection (audit/debug)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM records WHERE collection=? ORDER BY seq ASC",
                (collection,),
            ).fetchall()
        for r in rows:
            yield self._row_to_version(r)

    @staticmethod
    def _row_to_version(row: sqlite3.Row) -> Version:
        return Version(
            collection=row["collection"],
            key=row["key"],
            version=row["version"],
            value=json.loads(row["value"]),
            content_hash=row["content_hash"],
            author=row["author"],
            ts=row["ts"],
            deleted=bool(row["deleted"]),
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "ImmutableStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
