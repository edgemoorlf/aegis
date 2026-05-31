"""Tests for LLMVerifierAgent (Phase 3)."""

from __future__ import annotations

import json
import time

import pytest

from aegis import (
    APPEND,
    READ,
    TOMBSTONE,
    Capability,
    DataSelector,
    LLMVerifierAgent,
    MockLLMClient,
    Verdict,
    VerificationError,
)

POLICY = "Agents may only read from the ledger collection."


def _cap(
    collection: str = "ledger",
    key: str | None = None,
    ops: frozenset[str] | None = None,
    ttl: float = 3600.0,
) -> Capability:
    return Capability(
        selector=DataSelector(collection=collection, key=key),
        operations=ops if ops is not None else frozenset({READ, APPEND}),
        agent_id="agent-a",
        issued_by="admin",
        not_after=time.time() + ttl,
    )


def _verifier(response: str) -> LLMVerifierAgent:
    return LLMVerifierAgent(MockLLMClient(response))


def _approved(reason: str = "ok") -> str:
    return json.dumps({"approved": True, "reason": reason, "narrowed": None})


def _rejected(reason: str, narrowed: dict | None = None) -> str:
    return json.dumps({"approved": False, "reason": reason, "narrowed": narrowed})


# -- approval ----------------------------------------------------------------

def test_review_returns_verdict() -> None:
    v = _verifier(_approved()).review(_cap(), policy=POLICY)
    assert isinstance(v, Verdict)
    assert v.approved is True
    assert v.narrowed is None


def test_review_approved_reason_preserved() -> None:
    v = _verifier(_approved("least-privilege confirmed")).review(_cap(), policy=POLICY)
    assert "least-privilege" in v.reason


# -- rejection without narrowing ---------------------------------------------

def test_review_rejected_no_narrowing() -> None:
    v = _verifier(_rejected("wrong collection")).review(_cap(), policy=POLICY)
    assert v.approved is False
    assert v.narrowed is None


# -- rejection with narrowing ------------------------------------------------

def test_review_narrows_operations() -> None:
    narrowed_spec = {"operations": ["read"]}
    v = _verifier(_rejected("append not needed", narrowed_spec)).review(
        _cap(ops=frozenset({READ, APPEND})), policy=POLICY
    )
    assert v.approved is False
    assert v.narrowed is not None
    assert v.narrowed.operations == frozenset({READ})


def test_review_narrows_key() -> None:
    narrowed_spec = {"key": "balance"}
    v = _verifier(_rejected("too broad", narrowed_spec)).review(
        _cap(), policy=POLICY
    )
    assert v.narrowed is not None
    assert v.narrowed.selector.key == "balance"


def test_review_narrows_ttl() -> None:
    narrowed_spec = {"ttl_seconds": 600}
    v = _verifier(_rejected("ttl too long", narrowed_spec)).review(
        _cap(ttl=3600.0), policy=POLICY
    )
    assert v.narrowed is not None
    assert v.narrowed.not_after <= time.time() + 601


def test_review_narrowing_cannot_add_ops() -> None:
    narrowed_spec = {"operations": ["read", "tombstone"]}
    v = _verifier(_rejected("needs narrowing", narrowed_spec)).review(
        _cap(ops=frozenset({READ})), policy=POLICY
    )
    # tombstone not in base ops → must be silently clamped to {read}
    assert v.narrowed is not None
    assert TOMBSTONE not in v.narrowed.operations
    assert READ in v.narrowed.operations


def test_review_narrowing_cannot_extend_ttl() -> None:
    """Verifier proposing a longer TTL must be clamped to the original."""
    base = _cap(ttl=600.0)
    narrowed_spec = {"ttl_seconds": 99999}
    v = _verifier(_rejected("narrowing", narrowed_spec)).review(base, policy=POLICY)
    assert v.narrowed is not None
    assert v.narrowed.not_after <= base.not_after + 1


# -- markdown output tolerance -----------------------------------------------

def test_review_handles_fenced_json() -> None:
    fenced = "```json\n" + _approved() + "\n```"
    v = LLMVerifierAgent(MockLLMClient(fenced)).review(_cap(), policy=POLICY)
    assert v.approved is True


# -- error paths -------------------------------------------------------------

def test_review_raises_on_non_json() -> None:
    v_agent = _verifier("I cannot review this.")
    with pytest.raises(VerificationError):
        v_agent.review(_cap(), policy=POLICY)


def test_review_raises_on_missing_approved_field() -> None:
    bad = json.dumps({"reason": "ok", "narrowed": None})
    v_agent = _verifier(bad)
    with pytest.raises(VerificationError):
        v_agent.review(_cap(), policy=POLICY)
