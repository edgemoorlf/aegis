
import pytest

from aegis import AuditLog, TamperError


def test_append_and_verify_chain():
    with AuditLog() as log:
        log.append("agent-a", "data.read", "docs/readme")
        log.append("agent-b", "data.append", "docs/readme")
        assert log.verify() is True


def test_chain_links_entries():
    with AuditLog() as log:
        e1 = log.append("a", "x", "t")
        e2 = log.append("b", "y", "t")
        assert e2.prev_hash == e1.entry_hash
        assert e1.prev_hash == "0" * 64  # genesis


def test_query_filters():
    with AuditLog() as log:
        log.append("agent-a", "data.read", "docs/k")
        log.append("agent-b", "data.append", "docs/k")
        log.append("agent-a", "data.read", "docs/other")
        assert len(log.entries(actor="agent-a")) == 2
        assert len(log.entries(action="data.append")) == 1
        assert len(log.entries(target="docs/k")) == 2


def test_tamper_with_content_is_detected():
    log = AuditLog(":memory:")
    log.append("a", "data.read", "docs/secret")
    log.append("b", "data.read", "docs/secret")
    # Simulate an attacker editing a past entry's target directly in storage.
    log._conn.execute("UPDATE audit SET target='docs/innocent' WHERE seq=1")
    log._conn.commit()
    with pytest.raises(TamperError):
        log.verify()
    log.close()


def test_tamper_by_deletion_is_detected():
    log = AuditLog(":memory:")
    log.append("a", "x", "t")
    log.append("b", "y", "t")
    log.append("c", "z", "t")
    # Delete the middle entry — breaks the prev_hash link of the next one.
    log._conn.execute("DELETE FROM audit WHERE seq=2")
    log._conn.commit()
    with pytest.raises(TamperError):
        log.verify()
    log.close()


def test_capability_id_and_details_recorded():
    with AuditLog() as log:
        e = log.append(
            "agent-a",
            "capability.issue",
            "cap-123",
            capability_id="cap-123",
            details={"ops": ["read"], "collection": "docs"},
        )
        assert e.capability_id == "cap-123"
        assert e.details["ops"] == ["read"]
