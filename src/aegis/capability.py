"""Capability tokens — the access plane (Phase 2 foundation).

A capability scopes *which data*, *which operations*, *for how long*, and *by
whom*. The enforcement broker (Phase 2) and the LLM generator + verifier loop
(Phase 3) build on this schema. v1 ships the schema, a signature scheme, and
attenuation; the full broker/enforcement service is scaffolded in broker.py.

Design note: capabilities are *attenuable* — a holder can derive a strictly
narrower capability (fewer ops, tighter selector, shorter TTL) without talking
to the issuer, but can never broaden one. This is the macaroon/biscuit property
and is what makes least-privilege delegation cheap.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, replace
from hashlib import sha256
from typing import Optional

# Operations are deliberately coarse in v1; refine toward cell/semantic later.
READ = "read"
APPEND = "append"
TOMBSTONE = "tombstone"
ALL_OPS = frozenset({READ, APPEND, TOMBSTONE})


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class DataSelector:
    """Which data a capability applies to.

    `key` of None means the whole collection. Refinement (column/cell/semantic
    selectors) is a documented open question in PLAN.md.
    """

    collection: str
    key: Optional[str] = None

    def matches(self, collection: str, key: str) -> bool:
        if self.collection != collection:
            return False
        return self.key is None or self.key == key

    def narrows(self, other: "DataSelector") -> bool:
        """True if `self` is no broader than `other`."""
        if self.collection != other.collection:
            return False
        if other.key is None:
            return True
        return self.key == other.key


@dataclass(frozen=True)
class Capability:
    selector: DataSelector
    operations: frozenset[str]
    agent_id: str
    issued_by: str
    not_after: float                      # epoch seconds
    capability_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    issued_at: float = field(default_factory=time.time)

    # -- predicates ----------------------------------------------------------

    def is_expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) >= self.not_after

    def permits(self, collection: str, key: str, op: str, now: Optional[float] = None) -> bool:
        return (
            not self.is_expired(now)
            and op in self.operations
            and self.selector.matches(collection, key)
        )

    # -- attenuation ---------------------------------------------------------

    def attenuate(
        self,
        *,
        operations: Optional[frozenset[str]] = None,
        selector: Optional[DataSelector] = None,
        not_after: Optional[float] = None,
    ) -> "Capability":
        """Derive a strictly narrower capability. Raises on any broadening."""
        new_ops = operations if operations is not None else self.operations
        if not new_ops <= self.operations:
            raise ValueError("attenuation cannot add operations")
        new_sel = selector if selector is not None else self.selector
        if not new_sel.narrows(self.selector):
            raise ValueError("attenuation cannot broaden the selector")
        new_exp = self.not_after if not_after is None else min(not_after, self.not_after)
        return replace(
            self,
            operations=new_ops,
            selector=new_sel,
            not_after=new_exp,
            capability_id=str(uuid.uuid4()),
            issued_at=time.time(),
        )

    # -- signing -------------------------------------------------------------

    def _payload(self) -> dict[str, object]:
        return {
            "capability_id": self.capability_id,
            "collection": self.selector.collection,
            "key": self.selector.key,
            "operations": sorted(self.operations),
            "agent_id": self.agent_id,
            "issued_by": self.issued_by,
            "issued_at": self.issued_at,
            "not_after": self.not_after,
        }

    def sign(self, secret: bytes) -> str:
        """HMAC-style signature (v1 uses a shared secret; swap for asymmetric/biscuit later)."""
        material = secret + _canonical(self._payload()).encode("utf-8")
        return sha256(material).hexdigest()

    def verify_signature(self, signature: str, secret: bytes) -> bool:
        return self.sign(secret) == signature
