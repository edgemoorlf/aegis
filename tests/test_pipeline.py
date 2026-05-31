"""Tests for CapabilityPipeline (Phase 3 — end-to-end NL → token)."""

from __future__ import annotations

import json

import pytest

from aegis import (
    APPEND,
    READ,
    AuditLog,
    LLMCapabilityGenerator,
    LLMVerifierAgent,
    MockLLMClient,
    PipelineError,
    SQLiteCapabilityBroker,
)
from aegis.pipeline import CapabilityPipeline

SECRET = b"pipeline-test-secret-32-bytes-!!"
POLICY = "Agents may only read from the ledger collection."
TASK = "Read the balance for a customer."
SCHEMA: dict = {"collections": {"ledger": {}}}
AGENT_ID = "agent-a"


def _gen_response(ops: list[str] = None, ttl: int = 3600) -> str:
    return json.dumps({
        "collection": "ledger",
        "key": None,
        "operations": ops or ["read"],
        "ttl_seconds": ttl,
        "reasoning": "read-only",
    })


def _verdict(approved: bool, reason: str = "ok", narrowed: dict | None = None) -> str:
    return json.dumps({"approved": approved, "reason": reason, "narrowed": narrowed})


def _setup(gen_resp: str, ver_resp: str) -> CapabilityPipeline:
    audit = AuditLog()
    broker = SQLiteCapabilityBroker(audit, secret=SECRET)
    gen = LLMCapabilityGenerator(MockLLMClient(gen_resp), "admin")
    ver = LLMVerifierAgent(MockLLMClient(ver_resp))
    return CapabilityPipeline(gen, ver, broker, audit)


# -- happy path --------------------------------------------------------------

def test_pipeline_returns_token_on_first_approval() -> None:
    pipeline = _setup(_gen_response(), _verdict(True))
    token = pipeline.issue(
        agent_id=AGENT_ID, policy=POLICY, task=TASK, schema=SCHEMA
    )
    assert isinstance(token, str) and len(token) > 0


def test_issued_token_is_checkable() -> None:
    audit = AuditLog()
    broker = SQLiteCapabilityBroker(audit, secret=SECRET)
    gen = LLMCapabilityGenerator(MockLLMClient(_gen_response()), "admin")
    ver = LLMVerifierAgent(MockLLMClient(_verdict(True)))
    pipeline = CapabilityPipeline(gen, ver, broker, audit)
    token = pipeline.issue(agent_id=AGENT_ID, policy=POLICY, task=TASK, schema=SCHEMA)
    assert broker.check(token, "ledger", "balance", READ) is True


# -- narrowing loop ----------------------------------------------------------

def test_pipeline_applies_narrowing_and_approves() -> None:
    """First verdict rejects with a narrowing; second verdict approves."""
    audit = AuditLog()
    broker = SQLiteCapabilityBroker(audit, secret=SECRET)
    # Generator returns read+append; verifier rejects first, narrows to read-only, then approves
    gen = LLMCapabilityGenerator(
        MockLLMClient(_gen_response(ops=["read", "append"])), "admin"
    )
    responses = [
        _verdict(False, "append not needed", {"operations": ["read"]}),
        _verdict(True, "approved after narrowing"),
    ]
    response_iter = iter(responses)
    ver = LLMVerifierAgent(MockLLMClient(lambda s, u: next(response_iter)))
    pipeline = CapabilityPipeline(gen, ver, broker, audit, max_rounds=3)
    token = pipeline.issue(agent_id=AGENT_ID, policy=POLICY, task=TASK, schema=SCHEMA)
    cap = broker.decode(token)
    assert cap.operations == frozenset({READ})
    assert APPEND not in cap.operations


# -- error paths -------------------------------------------------------------

def test_pipeline_raises_on_rejection_without_narrowing() -> None:
    pipeline = _setup(_gen_response(), _verdict(False, "wrong collection"))
    with pytest.raises(PipelineError, match="without providing a narrowing"):
        pipeline.issue(agent_id=AGENT_ID, policy=POLICY, task=TASK, schema=SCHEMA)


def test_pipeline_raises_after_max_rounds() -> None:
    audit = AuditLog()
    broker = SQLiteCapabilityBroker(audit, secret=SECRET)
    gen = LLMCapabilityGenerator(MockLLMClient(_gen_response(ops=["read", "append"])), "admin")
    # Verifier always rejects with narrowing → never approves → exceeds max_rounds
    ver = LLMVerifierAgent(
        MockLLMClient(_verdict(False, "still too broad", {"operations": ["read"]}))
    )
    pipeline = CapabilityPipeline(gen, ver, broker, audit, max_rounds=2)
    with pytest.raises(PipelineError, match="not approved after"):
        pipeline.issue(agent_id=AGENT_ID, policy=POLICY, task=TASK, schema=SCHEMA)


def test_pipeline_rejects_shared_llm_client() -> None:
    audit = AuditLog()
    broker = SQLiteCapabilityBroker(audit, secret=SECRET)
    shared_llm = MockLLMClient(_gen_response())
    gen = LLMCapabilityGenerator(shared_llm, "admin")
    ver = LLMVerifierAgent(shared_llm)  # same instance — should be rejected
    with pytest.raises(ValueError, match="separate LLMClient"):
        CapabilityPipeline(gen, ver, broker, audit)


# -- audit trail -------------------------------------------------------------

def test_pipeline_writes_generate_and_verify_audit_entries() -> None:
    audit = AuditLog()
    broker = SQLiteCapabilityBroker(audit, secret=SECRET)
    gen = LLMCapabilityGenerator(MockLLMClient(_gen_response()), "admin")
    ver = LLMVerifierAgent(MockLLMClient(_verdict(True)))
    pipeline = CapabilityPipeline(gen, ver, broker, audit)
    pipeline.issue(agent_id=AGENT_ID, policy=POLICY, task=TASK, schema=SCHEMA)
    assert len(audit.entries(action="capability.generate")) >= 1
    assert len(audit.entries(action="capability.verify")) >= 1
    assert len(audit.entries(action="capability.issue")) == 1


def test_audit_chain_valid_after_pipeline() -> None:
    audit = AuditLog()
    broker = SQLiteCapabilityBroker(audit, secret=SECRET)
    gen = LLMCapabilityGenerator(MockLLMClient(_gen_response()), "admin")
    ver = LLMVerifierAgent(MockLLMClient(_verdict(True)))
    pipeline = CapabilityPipeline(gen, ver, broker, audit)
    pipeline.issue(agent_id=AGENT_ID, policy=POLICY, task=TASK, schema=SCHEMA)
    assert audit.verify() is True
