"""Tests for SQLiteCapabilityBroker (Phase 2)."""

from __future__ import annotations

import time

import pytest

from aegis import (
    APPEND,
    READ,
    TOMBSTONE,
    AuditLog,
    Capability,
    DataSelector,
    SQLiteCapabilityBroker,
)

SECRET = b"test-secret-32-bytes-long-enough"


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog()


@pytest.fixture
def broker(audit: AuditLog) -> SQLiteCapabilityBroker:
    return SQLiteCapabilityBroker(audit, secret=SECRET)


@pytest.fixture
def cap() -> Capability:
    return Capability(
        selector=DataSelector("ledger"),
        operations=frozenset({READ, APPEND}),
        agent_id="agent-a",
        issued_by="admin",
        not_after=time.time() + 3600,
    )


# -- issuance ----------------------------------------------------------------

def test_issue_returns_non_empty_token(broker: SQLiteCapabilityBroker, cap: Capability) -> None:
    token = broker.issue(cap)
    assert isinstance(token, str) and len(token) > 0


def test_issue_is_idempotent(broker: SQLiteCapabilityBroker, cap: Capability) -> None:
    t1 = broker.issue(cap)
    t2 = broker.issue(cap)
    assert t1 == t2


def test_issue_writes_audit_entry(
    broker: SQLiteCapabilityBroker, audit: AuditLog, cap: Capability
) -> None:
    broker.issue(cap)
    entries = audit.entries(action="capability.issue")
    assert len(entries) == 1
    e = entries[0]
    assert e.capability_id == cap.capability_id
    assert e.actor == "admin"
    assert e.details["agent_id"] == "agent-a"


# -- check: allow paths ------------------------------------------------------

def test_check_allows_registered_read(
    broker: SQLiteCapabilityBroker, cap: Capability
) -> None:
    token = broker.issue(cap)
    assert broker.check(token, "ledger", "balance", READ) is True


def test_check_allows_registered_append(
    broker: SQLiteCapabilityBroker, cap: Capability
) -> None:
    token = broker.issue(cap)
    assert broker.check(token, "ledger", "balance", APPEND) is True


def test_check_allowed_writes_audit_entry(
    broker: SQLiteCapabilityBroker, audit: AuditLog, cap: Capability
) -> None:
    token = broker.issue(cap)
    broker.check(token, "ledger", "balance", READ)
    entries = audit.entries(action="capability.check.allowed")
    assert len(entries) == 1
    assert entries[0].details["op"] == READ


# -- check: deny paths -------------------------------------------------------

def test_check_denies_unregistered_token(
    broker: SQLiteCapabilityBroker, cap: Capability
) -> None:
    # Token signed with the same secret but never issued through the broker.
    token = cap.to_token(SECRET)
    assert broker.check(token, "ledger", "balance", READ) is False


def test_check_denies_after_revocation(
    broker: SQLiteCapabilityBroker, cap: Capability
) -> None:
    token = broker.issue(cap)
    broker.revoke(cap.capability_id, by="admin")
    assert broker.check(token, "ledger", "balance", READ) is False


def test_check_denies_disallowed_op(
    broker: SQLiteCapabilityBroker, cap: Capability
) -> None:
    token = broker.issue(cap)
    assert broker.check(token, "ledger", "balance", TOMBSTONE) is False


def test_check_denies_wrong_collection(
    broker: SQLiteCapabilityBroker, cap: Capability
) -> None:
    token = broker.issue(cap)
    assert broker.check(token, "other", "balance", READ) is False


def test_check_denies_expired_token(broker: SQLiteCapabilityBroker) -> None:
    expired = Capability(
        selector=DataSelector("ledger"),
        operations=frozenset({READ}),
        agent_id="agent-a",
        issued_by="admin",
        not_after=time.time() - 1,
    )
    token = broker.issue(expired)
    assert broker.check(token, "ledger", "balance", READ) is False


def test_check_denies_malformed_token(broker: SQLiteCapabilityBroker) -> None:
    assert broker.check("not-a-valid-token", "ledger", "key", READ) is False


def test_check_denied_writes_audit_entry(
    broker: SQLiteCapabilityBroker, audit: AuditLog, cap: Capability
) -> None:
    broker.issue(cap)
    broker.revoke(cap.capability_id, by="admin")
    broker.check(broker.issue(cap), "ledger", "balance", READ)
    # The second issue is idempotent; the revocation still stands
    denied = audit.entries(action="capability.check.denied")
    assert any(e.details.get("reason") == "revoked" for e in denied)


# -- revocation --------------------------------------------------------------

def test_revoke_writes_audit_entry(
    broker: SQLiteCapabilityBroker, audit: AuditLog, cap: Capability
) -> None:
    broker.issue(cap)
    broker.revoke(cap.capability_id, by="admin")
    entries = audit.entries(action="capability.revoke")
    assert len(entries) == 1
    assert entries[0].capability_id == cap.capability_id


# -- decode ------------------------------------------------------------------

def test_decode_round_trips_capability(
    broker: SQLiteCapabilityBroker, cap: Capability
) -> None:
    token = broker.issue(cap)
    decoded = broker.decode(token)
    assert decoded.capability_id == cap.capability_id
    assert decoded.agent_id == cap.agent_id
    assert decoded.operations == cap.operations
    assert decoded.selector == cap.selector


def test_decode_raises_on_invalid_token(broker: SQLiteCapabilityBroker) -> None:
    with pytest.raises(ValueError):
        broker.decode("garbage")


# -- attenuation round-trip --------------------------------------------------

def test_attenuated_token_check(broker: SQLiteCapabilityBroker, cap: Capability) -> None:
    broker.issue(cap)
    narrow = cap.attenuate(operations=frozenset({READ}))
    narrow_token = broker.issue(narrow)
    assert broker.check(narrow_token, "ledger", "balance", READ) is True
    assert broker.check(narrow_token, "ledger", "balance", APPEND) is False
