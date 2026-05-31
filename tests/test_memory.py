"""Tests for SQLiteMemoryLayer (Phase 4)."""

from __future__ import annotations

import time

from aegis import (
    APPEND,
    READ,
    TOMBSTONE,
    AuditLog,
    Capability,
    DataSelector,
    EnforcedStore,
    ImmutableStore,
    MemoryEntry,
    SQLiteCapabilityBroker,
    SQLiteMemoryLayer,
)

SECRET = b"memory-test-secret-32-bytes-!!!!"


def _setup() -> tuple[EnforcedStore, SQLiteCapabilityBroker, AuditLog, SQLiteMemoryLayer]:
    audit = AuditLog()
    store = ImmutableStore()
    broker = SQLiteCapabilityBroker(audit, secret=SECRET)
    estore = EnforcedStore(store, broker, audit)
    memory = SQLiteMemoryLayer(audit)
    return estore, broker, audit, memory


def _issue(
    broker: SQLiteCapabilityBroker,
    collection: str = "ledger",
    ops: frozenset[str] | None = None,
    agent_id: str = "agent-a",
) -> str:
    cap = Capability(
        selector=DataSelector(collection),
        operations=ops if ops is not None else frozenset({READ, APPEND, TOMBSTONE}),
        agent_id=agent_id,
        issued_by="admin",
        not_after=time.time() + 3600,
    )
    return broker.issue(cap)


# -- write + snapshot --------------------------------------------------------

def test_write_returns_memory_id() -> None:
    _, _, _, memory = _setup()
    mid = memory.write("agent-a", {"fact": "x=1"}, source_version="ledger/k@1")
    assert isinstance(mid, str) and len(mid) > 0


def test_snapshot_returns_written_memories() -> None:
    _, _, _, memory = _setup()
    memory.write("agent-a", {"fact": "x=1"}, source_version="ledger/k@1")
    memory.write("agent-a", {"fact": "x=2"}, source_version="ledger/k@2")
    snap = memory.snapshot("agent-a")
    assert len(snap) == 2


def test_snapshot_is_empty_for_unknown_agent() -> None:
    _, _, _, memory = _setup()
    assert memory.snapshot("nobody") == {}


def test_snapshot_isolates_agents() -> None:
    _, _, _, memory = _setup()
    memory.write("agent-a", {"v": 1}, source_version="ledger/k@1")
    memory.write("agent-b", {"v": 2}, source_version="ledger/k@1")
    assert len(memory.snapshot("agent-a")) == 1
    assert len(memory.snapshot("agent-b")) == 1


def test_memory_entries_are_correct_type() -> None:
    _, _, _, memory = _setup()
    mid = memory.write("agent-a", {"val": 42}, source_version="col/key@3")
    snap = memory.snapshot("agent-a")
    entry = snap[mid]
    assert isinstance(entry, MemoryEntry)
    assert entry.content == {"val": 42}
    assert entry.source_version == "col/key@3"
    assert entry.agent_id == "agent-a"


def test_get_returns_memory_entry() -> None:
    _, _, _, memory = _setup()
    mid = memory.write("agent-a", {"x": 1}, source_version="col/k@1")
    entry = memory.get(mid)
    assert entry is not None
    assert entry.memory_id == mid


def test_get_returns_none_for_unknown_id() -> None:
    _, _, _, memory = _setup()
    assert memory.get("nonexistent-uuid") is None


# -- divergence: unverified source -------------------------------------------

def test_no_divergence_when_source_in_audit_log() -> None:
    """A memory written from a version that appears in data.read → no divergence."""
    estore, broker, _, memory = _setup()
    # Write data first, then read it with the enforced store
    token_rw = _issue(broker)
    estore.append(token_rw, "ledger", "balance", {"amount": 100})
    read_v = estore.read(token_rw, "ledger", "balance")
    source_version = f"ledger/balance@{read_v.version}"
    memory.write("agent-a", {"summary": "100"}, source_version=source_version)

    divergences = memory.detect_divergence("agent-a")
    assert divergences == []


def test_divergence_unverified_source() -> None:
    """A memory with a source_version not in the audit log → flagged."""
    _, _, _, memory = _setup()
    memory.write("agent-a", {"fact": "made up"}, source_version="ledger/balance@99")
    divs = memory.detect_divergence("agent-a")
    assert len(divs) == 1
    assert divs[0]["type"] == "unverified_source"
    assert divs[0]["source_version"] == "ledger/balance@99"


def test_divergence_no_false_positive_for_empty_memory() -> None:
    _, _, _, memory = _setup()
    assert memory.detect_divergence("agent-a") == []


# -- divergence: cross-agent conflict ----------------------------------------

def test_cross_agent_conflict_detected() -> None:
    """Two agents, same source_version, different content → conflict."""
    _, _, _, memory = _setup()
    # Both agents claim to have read the same version
    memory.write("agent-a", {"balance": 100}, source_version="ledger/balance@1")
    memory.write("agent-b", {"balance": 999}, source_version="ledger/balance@1")
    # Neither has an audit log entry, so both are "unverified" — but we also want
    # cross-agent conflict reported for agent-a
    divs = memory.detect_divergence("agent-a")
    types = {d["type"] for d in divs}
    assert "cross_agent_conflict" in types
    conflict = next(d for d in divs if d["type"] == "cross_agent_conflict")
    assert conflict["conflicting_agent_id"] == "agent-b"
    assert conflict["source_version"] == "ledger/balance@1"


def test_no_cross_agent_conflict_when_content_matches() -> None:
    """Two agents with same source AND same content — not a conflict."""
    estore, broker, _, memory = _setup()
    # Both agents read the same data from the store
    token_a = _issue(broker, agent_id="agent-a")
    token_b = _issue(broker, agent_id="agent-b")
    estore.append(token_a, "ledger", "balance", {"amount": 100})
    v_a = estore.read(token_a, "ledger", "balance")
    estore.read(token_b, "ledger", "balance")
    src = f"ledger/balance@{v_a.version}"
    memory.write("agent-a", {"amount": 100}, source_version=src)
    memory.write("agent-b", {"amount": 100}, source_version=src)
    divs = memory.detect_divergence("agent-a")
    conflicts = [d for d in divs if d["type"] == "cross_agent_conflict"]
    assert conflicts == []


# -- immutability ------------------------------------------------------------

def test_write_is_append_only() -> None:
    """Multiple writes accumulate; there is no overwrite."""
    _, _, _, memory = _setup()
    memory.write("agent-a", {"v": 1}, source_version="col/k@1")
    memory.write("agent-a", {"v": 2}, source_version="col/k@2")
    memory.write("agent-a", {"v": 3}, source_version="col/k@3")
    assert len(memory.snapshot("agent-a")) == 3
