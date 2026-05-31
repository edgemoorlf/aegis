"""Capability-enforced data access layer (Phase 2).

Wraps ImmutableStore with deny-by-default capability enforcement. Every
read, append, and tombstone requires a valid, unexpired, unrevoked capability
token whose selector covers the target (collection, key) and whose operations
include the requested op.

Successful operations are written to the AuditLog as data.read / data.append /
data.tombstone entries. Denial events are written by the broker's check() call,
so the audit trail is complete whether access is granted or refused.
"""

from __future__ import annotations

from typing import Any, Optional

from .audit import AuditLog
from .broker import CapabilityBroker
from .capability import APPEND, READ, TOMBSTONE, Capability
from .store import ImmutableStore, Version


class AccessDeniedError(PermissionError):
    """Raised when a capability check fails at the data access layer."""


class EnforcedStore:
    """ImmutableStore with capability-based access enforcement.

    The broker is the single source of authorization truth. EnforcedStore
    calls broker.check() before every operation and raises AccessDeniedError
    on denial. Successful accesses are attributed to the agent_id carried in
    the capability token, not to a caller-supplied string.
    """

    def __init__(
        self,
        store: ImmutableStore,
        broker: CapabilityBroker,
        audit_log: AuditLog,
    ) -> None:
        self._store = store
        self._broker = broker
        self._audit = audit_log

    def _require(self, token: str, collection: str, key: str, op: str) -> Capability:
        """Enforce the capability check; return the decoded Capability on success."""
        if not self._broker.check(token, collection, key, op):
            raise AccessDeniedError(
                f"capability check denied: {op} on {collection}/{key}"
            )
        return self._broker.decode(token)

    # -- write operations ----------------------------------------------------

    def append(self, token: str, collection: str, key: str, value: Any) -> Version:
        """Append a new version. Requires APPEND capability on (collection, key)."""
        cap = self._require(token, collection, key, APPEND)
        version = self._store.append(collection, key, value, author=cap.agent_id)
        self._audit.append(
            cap.agent_id,
            "data.append",
            f"{collection}/{key}",
            capability_id=cap.capability_id,
            details={"version": version.version, "content_hash": version.content_hash},
        )
        return version

    def tombstone(self, token: str, collection: str, key: str) -> Version:
        """Logically delete a key. Requires TOMBSTONE capability on (collection, key)."""
        cap = self._require(token, collection, key, TOMBSTONE)
        version = self._store.tombstone(collection, key, author=cap.agent_id)
        self._audit.append(
            cap.agent_id,
            "data.tombstone",
            f"{collection}/{key}",
            capability_id=cap.capability_id,
            details={"version": version.version},
        )
        return version

    # -- read operations -----------------------------------------------------

    def read(
        self,
        token: str,
        collection: str,
        key: str,
        *,
        as_of_version: Optional[int] = None,
        as_of_ts: Optional[float] = None,
    ) -> Version:
        """Read the latest version (or a time-traveled version). Requires READ."""
        cap = self._require(token, collection, key, READ)
        version = self._store.read(
            collection, key,
            as_of_version=as_of_version,
            as_of_ts=as_of_ts,
        )
        self._audit.append(
            cap.agent_id,
            "data.read",
            f"{collection}/{key}",
            capability_id=cap.capability_id,
            details={"version": version.version},
        )
        return version

    def history(self, token: str, collection: str, key: str) -> list[Version]:
        """Full version history for a key. Requires READ on (collection, key)."""
        cap = self._require(token, collection, key, READ)
        versions = self._store.history(collection, key)
        self._audit.append(
            cap.agent_id,
            "data.history",
            f"{collection}/{key}",
            capability_id=cap.capability_id,
            details={"version_count": len(versions)},
        )
        return versions
