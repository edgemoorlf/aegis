"""Aegis — a data-centric, capability-based substrate for multi-agent systems.

Protect the data, not the sandbox.

v1 ships the foundation (Phase 1): an append-only versioned ImmutableStore and a
tamper-evident AuditLog, plus the Capability schema (Phase 2 foundation) and
forward interfaces for Phases 2-4.
"""

from .audit import AuditEntry, AuditLog, TamperError
from .capability import ALL_OPS, APPEND, READ, TOMBSTONE, Capability, DataSelector
from .store import ImmutableStore, TombstoneError, Version, content_hash

__version__ = "0.1.0"

__all__ = [
    "ImmutableStore",
    "Version",
    "TombstoneError",
    "content_hash",
    "AuditLog",
    "AuditEntry",
    "TamperError",
    "Capability",
    "DataSelector",
    "READ",
    "APPEND",
    "TOMBSTONE",
    "ALL_OPS",
    "__version__",
]
