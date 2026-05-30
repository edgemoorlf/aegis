import time

import pytest

from aegis import APPEND, READ, TOMBSTONE, Capability, DataSelector


def make_cap(**kw):
    defaults = dict(
        selector=DataSelector("docs"),
        operations=frozenset({READ, APPEND}),
        agent_id="agent-a",
        issued_by="broker",
        not_after=time.time() + 3600,
    )
    defaults.update(kw)
    return Capability(**defaults)


def test_permits_within_scope():
    cap = make_cap()
    assert cap.permits("docs", "anything", READ)
    assert cap.permits("docs", "anything", APPEND)
    assert not cap.permits("docs", "anything", TOMBSTONE)
    assert not cap.permits("other", "anything", READ)


def test_expiry_denies():
    cap = make_cap(not_after=time.time() - 1)
    assert cap.is_expired()
    assert not cap.permits("docs", "k", READ)


def test_key_scoped_selector():
    cap = make_cap(selector=DataSelector("docs", "readme"))
    assert cap.permits("docs", "readme", READ)
    assert not cap.permits("docs", "other", READ)


def test_attenuation_narrows_ops():
    cap = make_cap()
    narrowed = cap.attenuate(operations=frozenset({READ}))
    assert narrowed.operations == frozenset({READ})
    assert narrowed.capability_id != cap.capability_id


def test_attenuation_cannot_broaden_ops():
    cap = make_cap(operations=frozenset({READ}))
    with pytest.raises(ValueError):
        cap.attenuate(operations=frozenset({READ, APPEND}))


def test_attenuation_narrows_selector():
    cap = make_cap(selector=DataSelector("docs"))
    narrowed = cap.attenuate(selector=DataSelector("docs", "readme"))
    assert narrowed.permits("docs", "readme", READ)
    assert not narrowed.permits("docs", "other", READ)


def test_attenuation_cannot_broaden_selector():
    cap = make_cap(selector=DataSelector("docs", "readme"))
    with pytest.raises(ValueError):
        cap.attenuate(selector=DataSelector("docs"))  # broadening to whole collection


def test_attenuation_only_shortens_ttl():
    cap = make_cap(not_after=time.time() + 100)
    longer = cap.attenuate(not_after=time.time() + 10_000)
    assert longer.not_after <= cap.not_after  # cannot extend


def test_signature_roundtrip_and_tamper():
    secret = b"shared-secret"
    cap = make_cap()
    sig = cap.sign(secret)
    assert cap.verify_signature(sig, secret)
    assert not cap.verify_signature(sig, b"wrong-secret")
