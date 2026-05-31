"""Memory layer with provenance tracking and divergence detection (Phase 4).

Agent memories are derived views of the immutable store, never the source of
truth. Every memory is tagged with which data version it was derived from
(source_version), which agent wrote it, and when. This provenance allows:

  1. Divergence detection: verifying that a memory's source_version actually
     appears in the audit log as a data.read event by that agent.
  2. Cross-agent conflict detection: two agents hold memories from the same
     source that disagree in content.

source_version convention
─────────────────────────
Use ``"{collection}/{key}@{version_number}"`` where version_number is the
``Version.version`` integer from ImmutableStore. EnforcedStore.read() writes
exactly ``target = "collection/key"`` and ``details["version"] = N`` to the
audit log, so the compound key ``f"{target}@{N}"`` is the canonical form.

Example::

    v = estore.read(token, "ledger", "balance")
    mem_id = memory.write(
        "agent-a",
        {"summary": "balance is 100"},
        source_version=f"ledger/balance@{v.version}",
    )
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from .audit import AuditLog


@dataclass(frozen=True)
class MemoryEntry:
    """A single provenance-tagged agent memory (immutable once written)."""

    memory_id: str
    agent_id: str
    content: Any
    source_version: str  # e.g. "collection/key@version_number"
    ts: float


class SQLiteMemoryLayer:
    """Append-only, provenance-tagged memory store backed by SQLite.

    The underlying table is insert-only — no UPDATE or DELETE — preserving
    the never-delete principle for memories.

    Divergence detection compares each memory's source_version against the
    data.read entries in the audit log. A memory whose source cannot be traced
    to a legitimate read is flagged as "unverified_source". Two agents holding
    memories from the same source with different content are flagged as
    "cross_agent_conflict".
    """

    def __init__(self, audit_log: AuditLog, *, path: str = ":memory:") -> None:
        self._audit = audit_log
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memories (
                    memory_id      TEXT PRIMARY KEY,
                    agent_id       TEXT NOT NULL,
                    content        TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    ts             REAL NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent ON memories (agent_id)"
            )

    # -- MemoryLayer interface -----------------------------------------------

    def write(self, agent_id: str, content: Any, *, source_version: str) -> str:
        """Store a memory tagged with (agent_id, source_version, timestamp).

        Returns the new memory_id (a UUID string).
        """
        memory_id = str(uuid.uuid4())
        ts = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO memories (memory_id, agent_id, content, source_version, ts)
                   VALUES (?,?,?,?,?)""",
                (memory_id, agent_id, json.dumps(content, sort_keys=True), source_version, ts),
            )
        return memory_id

    def snapshot(self, agent_id: str) -> dict[str, MemoryEntry]:
        """All memories for *agent_id*, keyed by memory_id, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM memories WHERE agent_id=? ORDER BY ts ASC",
                (agent_id,),
            ).fetchall()
        return {
            row["memory_id"]: MemoryEntry(
                memory_id=row["memory_id"],
                agent_id=row["agent_id"],
                content=json.loads(row["content"]),
                source_version=row["source_version"],
                ts=row["ts"],
            )
            for row in rows
        }

    def detect_divergence(self, agent_id: str) -> list[dict[str, Any]]:
        """Compare memory provenance against the audit log.

        Returns a list of divergence reports. Each report is a dict with keys:
          - ``type``: "unverified_source" | "cross_agent_conflict"
          - ``memory_id``
          - ``agent_id``
          - ``source_version``
          - ``detail``: human-readable explanation

        For "cross_agent_conflict" reports, also includes
        ``conflicting_memory_id`` and ``conflicting_agent_id``.
        """
        memories = list(self.snapshot(agent_id).values())
        if not memories:
            return []

        verified = self._verified_sources(agent_id)
        divergences: list[dict[str, Any]] = []

        # --- unverified source check ----------------------------------------
        for mem in memories:
            if mem.source_version not in verified:
                divergences.append(
                    {
                        "type": "unverified_source",
                        "memory_id": mem.memory_id,
                        "agent_id": agent_id,
                        "source_version": mem.source_version,
                        "detail": (
                            f"Memory {mem.memory_id} claims source "
                            f"'{mem.source_version}' but no matching data.read "
                            f"found in audit log for agent '{agent_id}'"
                        ),
                    }
                )

        # --- cross-agent conflict check -------------------------------------
        other_agents = [a for a in self._all_agents() if a != agent_id]
        for other_id in other_agents:
            other_memories = list(self.snapshot(other_id).values())
            for mem in memories:
                for other_mem in other_memories:
                    if (
                        mem.source_version == other_mem.source_version
                        and json.dumps(mem.content, sort_keys=True)
                        != json.dumps(other_mem.content, sort_keys=True)
                    ):
                        divergences.append(
                            {
                                "type": "cross_agent_conflict",
                                "memory_id": mem.memory_id,
                                "conflicting_memory_id": other_mem.memory_id,
                                "agent_id": agent_id,
                                "conflicting_agent_id": other_id,
                                "source_version": mem.source_version,
                                "detail": (
                                    f"Agent '{agent_id}' (memory {mem.memory_id}) and "
                                    f"agent '{other_id}' (memory {other_mem.memory_id}) "
                                    f"hold different content from source "
                                    f"'{mem.source_version}'"
                                ),
                            }
                        )

        return divergences

    # -- helpers -------------------------------------------------------------

    def _verified_sources(self, agent_id: str) -> frozenset[str]:
        """Build the set of source_versions the agent legitimately read."""
        read_entries = self._audit.entries(actor=agent_id, action="data.read")
        verified: set[str] = set()
        for e in read_entries:
            version = e.details.get("version")
            if version is not None:
                verified.add(f"{e.target}@{version}")
        return frozenset(verified)

    def _all_agents(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT agent_id FROM memories"
            ).fetchall()
        return [r["agent_id"] for r in rows]

    def get(self, memory_id: str) -> Optional[MemoryEntry]:
        """Fetch a single memory entry by ID, or None if not found."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memories WHERE memory_id=?", (memory_id,)
            ).fetchone()
        if row is None:
            return None
        return MemoryEntry(
            memory_id=row["memory_id"],
            agent_id=row["agent_id"],
            content=json.loads(row["content"]),
            source_version=row["source_version"],
            ts=row["ts"],
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteMemoryLayer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
