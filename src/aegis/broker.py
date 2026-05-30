"""Forward-looking interfaces for Phases 2-4.

These are intentionally abstract. They make the target architecture concrete and
give contributors clear seams to implement against. v1 ships Phase 1 (store +
audit) as working code; the classes below raise NotImplementedError.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional, Protocol

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
