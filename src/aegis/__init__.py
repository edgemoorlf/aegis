"""Aegis — a data-centric, capability-based substrate for multi-agent systems.

Protect the data, not the sandbox.

v0.1 ships Phase 1 (ImmutableStore + AuditLog) and Phase 2 (Capability schema,
SQLiteCapabilityBroker, EnforcedStore). Phases 3-4 are scaffolded as interfaces.
"""

from .audit import AuditEntry, AuditLog, TamperError
from .broker import CapabilityBroker, SQLiteCapabilityBroker
from .capability import ALL_OPS, APPEND, READ, TOMBSTONE, Capability, DataSelector
from .enforced_store import AccessDeniedError, EnforcedStore
from .store import ImmutableStore, TombstoneError, Version, content_hash

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
    "__version__",
]
