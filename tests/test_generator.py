"""Tests for LLMCapabilityGenerator (Phase 3)."""

from __future__ import annotations

import json
import time

import pytest

from aegis import (
    APPEND,
    READ,
    Capability,
    CapabilityGenerationError,
    LLMCapabilityGenerator,
    MockLLMClient,
)

SCHEMA = {
    "collections": {
        "ledger": {"keys": ["balance", "transactions"], "description": "Financial records"}
    }
}
POLICY = "Agents may only read from the ledger collection."
TASK = "Read the current balance for a customer."
ISSUED_BY = "admin"
AGENT_ID = "agent-a"


def _generator(response: str) -> LLMCapabilityGenerator:
    return LLMCapabilityGenerator(MockLLMClient(response), ISSUED_BY)


def _valid_json(
    collection: str = "ledger",
    key: object = None,
    operations: list[str] | None = None,
    ttl: int = 3600,
) -> str:
    return json.dumps({
        "collection": collection,
        "key": key,
        "operations": operations or ["read"],
        "ttl_seconds": ttl,
        "reasoning": "read-only access to the balance key",
    })


# -- happy path --------------------------------------------------------------

def test_propose_returns_capability() -> None:
    gen = _generator(_valid_json())
    cap = gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)
    assert isinstance(cap, Capability)
    assert cap.agent_id == AGENT_ID
    assert cap.issued_by == ISSUED_BY
    assert cap.operations == frozenset({READ})
    assert cap.selector.collection == "ledger"
    assert cap.selector.key is None


def test_propose_specific_key() -> None:
    gen = _generator(_valid_json(key="balance"))
    cap = gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)
    assert cap.selector.key == "balance"


def test_propose_multiple_ops() -> None:
    gen = _generator(_valid_json(operations=["read", "append"]))
    cap = gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)
    assert cap.operations == frozenset({READ, APPEND})


def test_propose_ignores_invalid_op() -> None:
    gen = _generator(_valid_json(operations=["read", "fly"]))
    cap = gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)
    assert cap.operations == frozenset({READ})


def test_propose_sets_correct_expiry() -> None:
    gen = _generator(_valid_json(ttl=1800))
    before = time.time()
    cap = gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)
    assert cap.not_after >= before + 1800
    assert cap.not_after <= time.time() + 1800 + 1


def test_propose_agent_id_always_from_parameter() -> None:
    """The generator must use the caller's agent_id, not any id in the LLM output."""
    gen = _generator(_valid_json())
    cap = gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id="agent-specific")
    assert cap.agent_id == "agent-specific"


def test_propose_handles_markdown_fenced_json() -> None:
    fenced = "```json\n" + _valid_json() + "\n```"
    gen = _generator(fenced)
    cap = gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)
    assert cap.operations == frozenset({READ})


def test_propose_handles_json_in_prose() -> None:
    prose = "Sure! Here is the capability:\n" + _valid_json() + "\nHope that helps."
    gen = _generator(prose)
    cap = gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)
    assert cap.operations == frozenset({READ})


# -- error paths -------------------------------------------------------------

def test_propose_raises_on_non_json() -> None:
    gen = _generator("I cannot generate a capability for this task.")
    with pytest.raises(CapabilityGenerationError):
        gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)


def test_propose_raises_on_missing_collection() -> None:
    bad = json.dumps({"operations": ["read"], "ttl_seconds": 3600, "reasoning": "ok"})
    gen = _generator(bad)
    with pytest.raises(CapabilityGenerationError):
        gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)


def test_propose_raises_on_all_invalid_ops() -> None:
    bad = json.dumps({"collection": "ledger", "operations": ["fly", "dance"], "ttl_seconds": 3600})
    gen = _generator(bad)
    with pytest.raises(CapabilityGenerationError):
        gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)


def test_propose_raises_on_zero_ttl() -> None:
    bad = _valid_json(ttl=0)
    gen = _generator(bad)
    with pytest.raises(CapabilityGenerationError):
        gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)


def test_propose_uses_default_ttl_when_omitted() -> None:
    no_ttl = json.dumps({"collection": "ledger", "operations": ["read"], "reasoning": "ok"})
    gen = LLMCapabilityGenerator(MockLLMClient(no_ttl), ISSUED_BY, default_ttl_s=7200.0)
    before = time.time()
    cap = gen.propose(policy=POLICY, task=TASK, schema=SCHEMA, agent_id=AGENT_ID)
    assert cap.not_after >= before + 7200
