"""Aegis — a data-centric, capability-based substrate for multi-agent systems.

Protect the data, not the sandbox.

v0.1 ships Phases 1–4:
  Phase 1 — ImmutableStore + AuditLog (foundation)
  Phase 2 — Capability schema, SQLiteCapabilityBroker, EnforcedStore
  Phase 3 — LLMCapabilityGenerator, LLMVerifierAgent, CapabilityPipeline
  Phase 4 — SQLiteMemoryLayer with provenance + divergence detection
"""

from .audit import AuditEntry, AuditLog, TamperError
from .broker import CapabilityBroker, SQLiteCapabilityBroker
from .capability import ALL_OPS, APPEND, READ, TOMBSTONE, Capability, DataSelector
from .enforced_store import AccessDeniedError, EnforcedStore
from .generator import CapabilityGenerationError, LLMCapabilityGenerator
from .llm import LLMClient, LLMError, MockLLMClient, OllamaLLMClient
from .memory import MemoryEntry, SQLiteMemoryLayer
from .pipeline import CapabilityPipeline, PipelineError
from .store import ImmutableStore, TombstoneError, Version, content_hash
from .verifier import LLMVerifierAgent, Verdict, VerificationError

__version__ = "0.1.0"

__all__ = [
    # Phase 1 — store + audit
    "ImmutableStore",
    "Version",
    "TombstoneError",
    "content_hash",
    "AuditLog",
    "AuditEntry",
    "TamperError",
    # Phase 2 — capability schema
    "Capability",
    "DataSelector",
    "READ",
    "APPEND",
    "TOMBSTONE",
    "ALL_OPS",
    # Phase 2 — broker + enforcement
    "CapabilityBroker",
    "SQLiteCapabilityBroker",
    "EnforcedStore",
    "AccessDeniedError",
    # Phase 3 — LLM clients
    "LLMClient",
    "LLMError",
    "OllamaLLMClient",
    "MockLLMClient",
    # Phase 3 — generator + verifier
    "LLMCapabilityGenerator",
    "CapabilityGenerationError",
    "LLMVerifierAgent",
    "Verdict",
    "VerificationError",
    # Phase 3 — pipeline
    "CapabilityPipeline",
    "PipelineError",
    # Phase 4 — memory layer
    "SQLiteMemoryLayer",
    "MemoryEntry",
    "__version__",
]
