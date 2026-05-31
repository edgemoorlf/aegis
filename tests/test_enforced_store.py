"""Tests for EnforcedStore (Phase 2)."""

from __future__ import annotations

import time

import pytest

from aegis import (
    APPEND,
    READ,
    TOMBSTONE,
    AccessDeniedError,
    AuditLog,
    Capability,
    DataSelector,
    EnforcedStore,
    ImmutableStore,
    SQLiteCapabilityBroker,
)

SECRET = b"test-secret-32-bytes-long-enough"


def _make_store() -> tuple[ImmutableStore, SQLiteCapabilityBroker, AuditLog, EnforcedStore]:
    audit = AuditLog()
    store = ImmutableStore()
    broker = SQLiteCapabilityBroker(audit, secret=SECRET)
    estore = EnforcedStore(store, broker, audit)
    return store, broker, audit, estore


def _issue(
    broker: SQLiteCapabilityBroker,
    collection: str = "ledger",
    ops: frozenset[str] | None = None,
    agent_id: str = "agent-a",
    ttl: float = 3600,
) -> str:
    cap = Capability(
        selector=DataSelector(collection),
        operations=ops if ops is not None else frozenset({READ, APPEND, TOMBSTONE}),
        agent_id=agent_id,
        issued_by="admin",
        not_after=time.time() + ttl,
    )
    return broker.issue(cap)


# -- append ------------------------------------------------------------------

def test_append_succeeds_with_valid_token() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker)
    v = estore.append(token, "ledger", "balance", {"amount": 100})
    assert v.value == {"amount": 100}
    assert v.author == "agent-a"


def test_append_author_is_from_token_not_caller() -> None:
    """Author on the stored version must come from the capability, not a free param."""
    _, broker, _, estore = _make_store()
    token = _issue(broker, agent_id="agent-b")
    v = estore.append(token, "ledger", "k", {"x": 1})
    assert v.author == "agent-b"


def test_append_denied_bad_token() -> None:
    _, _, _, estore = _make_store()
    with pytest.raises(AccessDeniedError):
        estore.append("bad-token", "ledger", "balance", {"amount": 1})


def test_append_denied_wrong_collection() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker, collection="ledger")
    with pytest.raises(AccessDeniedError):
        estore.append(token, "secrets", "key", {"v": 1})


def test_append_denied_no_append_op() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker, ops=frozenset({READ}))
    with pytest.raises(AccessDeniedError):
        estore.append(token, "ledger", "balance", {"amount": 1})


def test_append_writes_audit_entry() -> None:
    _, broker, audit, estore = _make_store()
    token = _issue(broker)
    estore.append(token, "ledger", "balance", {"amount": 100})
    entries = audit.entries(action="data.append")
    assert len(entries) == 1
    assert entries[0].actor == "agent-a"
    assert entries[0].target == "ledger/balance"


# -- read --------------------------------------------------------------------

def test_read_succeeds_with_valid_token() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker)
    estore.append(token, "ledger", "balance", {"amount": 100})
    v = estore.read(token, "ledger", "balance")
    assert v.value == {"amount": 100}


def test_read_denied_bad_token() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker)
    estore.append(token, "ledger", "balance", {"amount": 100})
    with pytest.raises(AccessDeniedError):
        estore.read("bad-token", "ledger", "balance")


def test_read_denied_no_read_op() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker, ops=frozenset({APPEND}))
    estore.append(token, "ledger", "balance", {"amount": 100})
    read_only_barrier = _issue(broker, ops=frozenset({TOMBSTONE}))
    with pytest.raises(AccessDeniedError):
        estore.read(read_only_barrier, "ledger", "balance")


def test_read_time_travel_with_version() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker)
    estore.append(token, "ledger", "balance", {"amount": 100})
    estore.append(token, "ledger", "balance", {"amount": 80})
    v = estore.read(token, "ledger", "balance", as_of_version=1)
    assert v.value == {"amount": 100}


def test_read_writes_audit_entry() -> None:
    _, broker, audit, estore = _make_store()
    token = _issue(broker)
    estore.append(token, "ledger", "balance", {"amount": 100})
    estore.read(token, "ledger", "balance")
    entries = audit.entries(action="data.read")
    assert len(entries) == 1


# -- tombstone ---------------------------------------------------------------

def test_tombstone_succeeds_with_valid_token() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker)
    estore.append(token, "ledger", "balance", {"amount": 100})
    v = estore.tombstone(token, "ledger", "balance")
    assert v.is_tombstone


def test_tombstone_denied_no_tombstone_op() -> None:
    _, broker, _, estore = _make_store()
    token_rw = _issue(broker, ops=frozenset({READ, APPEND}))
    estore.append(token_rw, "ledger", "balance", {"amount": 100})
    with pytest.raises(AccessDeniedError):
        estore.tombstone(token_rw, "ledger", "balance")


def test_tombstone_writes_audit_entry() -> None:
    _, broker, audit, estore = _make_store()
    token = _issue(broker)
    estore.append(token, "ledger", "balance", {"amount": 100})
    estore.tombstone(token, "ledger", "balance")
    entries = audit.entries(action="data.tombstone")
    assert len(entries) == 1


# -- history -----------------------------------------------------------------

def test_history_returns_all_versions() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker)
    estore.append(token, "ledger", "balance", {"amount": 100})
    estore.append(token, "ledger", "balance", {"amount": 80})
    versions = estore.history(token, "ledger", "balance")
    assert len(versions) == 2


def test_history_denied_bad_token() -> None:
    _, _, _, estore = _make_store()
    with pytest.raises(AccessDeniedError):
        estore.history("bad-token", "ledger", "balance")


# -- revocation integration --------------------------------------------------

def test_revoked_token_denied_on_read() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker)
    cap = broker.decode(token)
    estore.append(token, "ledger", "balance", {"amount": 100})
    broker.revoke(cap.capability_id, by="admin")
    with pytest.raises(AccessDeniedError):
        estore.read(token, "ledger", "balance")


def test_revoked_token_denied_on_append() -> None:
    _, broker, _, estore = _make_store()
    token = _issue(broker)
    cap = broker.decode(token)
    broker.revoke(cap.capability_id, by="admin")
    with pytest.raises(AccessDeniedError):
        estore.append(token, "ledger", "balance", {"amount": 1})


# -- deny-by-default ---------------------------------------------------------

def test_deny_by_default_no_token() -> None:
    """Absolutely no token means no access."""
    _, _, _, estore = _make_store()
    with pytest.raises(AccessDeniedError):
        estore.read("", "ledger", "balance")


def test_underlying_store_unmodified_on_denial() -> None:
    """A denied write must not partially mutate the underlying store."""
    store, broker, _, estore = _make_store()
    token = _issue(broker, ops=frozenset({READ}))
    with pytest.raises(AccessDeniedError):
        estore.append(token, "ledger", "balance", {"amount": 1})
    assert store.read_or_none("ledger", "balance") is None


# -- audit chain integrity ---------------------------------------------------

def test_audit_chain_stays_valid_through_operations() -> None:
    _, broker, audit, estore = _make_store()
    token = _issue(broker)
    estore.append(token, "ledger", "balance", {"amount": 100})
    estore.read(token, "ledger", "balance")
    estore.tombstone(token, "ledger", "balance")
    assert audit.verify() is True
