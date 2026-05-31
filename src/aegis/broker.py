"""Capability broker — access plane (Phase 2).

Defines the CapabilityBroker ABC and the reference SQLiteCapabilityBroker
implementation. Phase 3 (LLM generation + verification) and Phase 4 (memory
layer) interfaces are scaffolded below as Protocols / ABCs.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Optional, Protocol

from .audit import AuditLog
from .capability import Capability


# -- Phase 2: Capability Broker + enforcement --------------------------------

class CapabilityBroker(ABC):
    """Issues, revokes, and expires capability tokens; the access plane.

    Every issuance and revocation MUST be written to the AuditLog. Enforcement
    is deny-by-default: absent a valid, unexpired, unrevoked capability, access
    is refused regardless of what code is running.
    """

    @abstractmethod
    def issue(self, capability: Capability) -> str:
        """Persist a capability and return its signed token. Audited."""

    @abstractmethod
    def revoke(self, capability_id: str, *, by: str) -> None:
        """Revoke before expiry. Audited."""

    @abstractmethod
    def check(self, token: str, collection: str, key: str, op: str) -> bool:
        """Deny-by-default enforcement decision. Audited."""

    @abstractmethod
    def decode(self, token: str) -> Capability:
        """Decode and verify a token. Raises ValueError on invalid/tampered token."""


class SQLiteCapabilityBroker(CapabilityBroker):
    """Reference implementation: SQLite-backed capability broker.

    All capabilities and revocations are stored in insert-only tables.
    Every issuance, revocation, and enforcement decision is written to the
    supplied AuditLog.

    The HMAC secret is shared between all parties that need to verify tokens
    (broker + EnforcedStore). In production, migrate to asymmetric signing
    (biscuit / macaroons) so the verification key can be public.

    Agent identity: v1 trusts the agent_id embedded in the capability token.
    In production, back this with SPIFFE/SPIRE or mTLS certificates so the
    agent_id cannot be spoofed by the holder of an attenuated token.
    """

    def __init__(
        self,
        audit_log: AuditLog,
        *,
        secret: bytes,
        path: str = ":memory:",
    ) -> None:
        self._audit = audit_log
        self._secret = secret
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS capabilities (
                    capability_id TEXT PRIMARY KEY,
                    agent_id      TEXT NOT NULL,
                    issued_by     TEXT NOT NULL,
                    issued_at     REAL NOT NULL,
                    not_after     REAL NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS revocations (
                    capability_id TEXT NOT NULL,
                    revoked_by    TEXT NOT NULL,
                    revoked_at    REAL NOT NULL
                )
                """
            )

    # -- CapabilityBroker interface ------------------------------------------

    def issue(self, capability: Capability) -> str:
        """Register a capability and return its signed token. Idempotent on re-issue."""
        token = capability.to_token(self._secret)
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT OR IGNORE INTO capabilities
                   (capability_id, agent_id, issued_by, issued_at, not_after)
                   VALUES (?,?,?,?,?)""",
                (
                    capability.capability_id,
                    capability.agent_id,
                    capability.issued_by,
                    capability.issued_at,
                    capability.not_after,
                ),
            )
        self._audit.append(
            capability.issued_by,
            "capability.issue",
            capability.capability_id,
            capability_id=capability.capability_id,
            details={
                "agent_id": capability.agent_id,
                "collection": capability.selector.collection,
                "key": capability.selector.key,
                "operations": sorted(capability.operations),
                "not_after": capability.not_after,
            },
        )
        return token

    def revoke(self, capability_id: str, *, by: str) -> None:
        """Record a revocation. Effective immediately on subsequent check() calls."""
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO revocations (capability_id, revoked_by, revoked_at) VALUES (?,?,?)",
                (capability_id, by, time.time()),
            )
        self._audit.append(
            by,
            "capability.revoke",
            capability_id,
            capability_id=capability_id,
            details={"revoked_by": by},
        )

    def check(self, token: str, collection: str, key: str, op: str) -> bool:
        """Deny-by-default enforcement. Every decision is written to the AuditLog."""
        # 1. Decode and verify token signature.
        try:
            cap = Capability.from_token(token, self._secret)
        except ValueError:
            self._audit.append(
                "unknown",
                "capability.check.denied",
                f"{collection}/{key}",
                details={"reason": "invalid_token", "op": op},
            )
            return False

        target = f"{collection}/{key}"

        # 2. Verify the capability was registered with this broker.
        with self._lock:
            registered = self._conn.execute(
                "SELECT 1 FROM capabilities WHERE capability_id=?",
                (cap.capability_id,),
            ).fetchone()
        if registered is None:
            self._audit.append(
                cap.agent_id,
                "capability.check.denied",
                target,
                capability_id=cap.capability_id,
                details={"reason": "not_registered", "op": op},
            )
            return False

        # 3. Check for revocation.
        with self._lock:
            revoked = self._conn.execute(
                "SELECT 1 FROM revocations WHERE capability_id=?",
                (cap.capability_id,),
            ).fetchone()
        if revoked is not None:
            self._audit.append(
                cap.agent_id,
                "capability.check.denied",
                target,
                capability_id=cap.capability_id,
                details={"reason": "revoked", "op": op},
            )
            return False

        # 4. Check expiry, selector, and operation.
        if not cap.permits(collection, key, op):
            reason = "expired" if cap.is_expired() else "selector_or_op_mismatch"
            self._audit.append(
                cap.agent_id,
                "capability.check.denied",
                target,
                capability_id=cap.capability_id,
                details={"reason": reason, "op": op},
            )
            return False

        self._audit.append(
            cap.agent_id,
            "capability.check.allowed",
            target,
            capability_id=cap.capability_id,
            details={"op": op},
        )
        return True

    def decode(self, token: str) -> Capability:
        """Decode and verify a token. Raises ValueError on invalid/tampered token."""
        return Capability.from_token(token, self._secret)

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteCapabilityBroker":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# -- Phase 3: LLM generation + verification ----------------------------------

class CapabilityGenerator(Protocol):
    """Turns natural-language policy + task + schema into a candidate capability.

    Runs against a *local* model by default (llama.cpp / Ollama / vLLM) so
    context never leaves the trust boundary.
    """

    def propose(self, *, policy: str, task: str, schema: dict[str, Any]) -> Capability: ...


class VerifierAgent(Protocol):
    """Independent critic that audits a proposed capability.

    MUST run in a separate model context from the generator to avoid
    self-justification. Returns an approval decision plus a narrowed capability
    when over-permissioning is detected.
    """

    def review(self, proposed: Capability, *, policy: str) -> "VerdictProtocol": ...


class VerdictProtocol(Protocol):
    approved: bool
    reason: str
    narrowed: Optional[Capability]


# -- Phase 4: Memory layer + discrepancy detection ---------------------------

class MemoryLayer(ABC):
    """Provenance-tagged, versioned agent memory.

    Cross-agent reads go through the CapabilityBroker like any other data
    access. Divergence is detected by comparing a memory snapshot against the
    authoritative AuditLog.
    """

    @abstractmethod
    def write(self, agent_id: str, content: Any, *, source_version: str) -> str:
        """Store a memory tagged with (agent_id, source_data_version, timestamp)."""

    @abstractmethod
    def snapshot(self, agent_id: str) -> dict[str, Any]:
        """Consistent point-in-time view of an agent's memory."""

    @abstractmethod
    def detect_divergence(self, agent_id: str) -> list[dict[str, Any]]:
        """Compare memory provenance against the audit log; report inconsistencies."""
