"""LLM-backed CapabilityGenerator (Phase 3).

Reads a natural-language policy, a task description, and a data schema, then
asks a local LLM to emit a minimal capability spec. The LLM output is treated
as untrusted input: structurally validated and schema-checked before being
converted to a typed Capability.

The generator must NOT share an LLMClient instance with LLMVerifierAgent —
the verifier must run in a separate model context to prevent self-justification
(see PLAN.md §Design Principles and THREAT_MODEL.md §Threat 2).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from .capability import APPEND, READ, TOMBSTONE, Capability, DataSelector
from .llm import LLMClient

_VALID_OPS: frozenset[str] = frozenset({READ, APPEND, TOMBSTONE})

_SYSTEM_PROMPT = """\
You are a capability specification generator for a data security system.
Given a natural-language access policy, a task description, and a data schema,
produce a MINIMAL capability specification following the principle of least privilege.
Grant only the operations and data scope strictly necessary for the stated task.

Output a single JSON object with exactly these fields and no other text:
{
  "collection": "<collection name from the schema>",
  "key": "<specific key to restrict access to, or null for the whole collection>",
  "operations": ["read" | "append" | "tombstone"],
  "ttl_seconds": <positive integer>,
  "reasoning": "<one sentence justifying the chosen scope>"
}

Rules:
- "operations" must be a non-empty subset of ["read", "append", "tombstone"].
- Include only operations the task explicitly requires. If the task only reads, omit "append" and "tombstone".
- Prefer a specific key over the whole collection when the task targets a single record.
- Keep ttl_seconds as short as practical for the task.
"""


def _extract_json(text: str) -> dict[str, Any]:
    """Extract the first JSON object from LLM output, tolerating markdown fences."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text.strip())
    try:
        return dict(json.loads(text))
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            return dict(json.loads(m.group()))
        raise ValueError(f"no JSON object found in LLM output: {text!r}")


class CapabilityGenerationError(ValueError):
    """Raised when the LLM output cannot be parsed into a valid Capability."""


class LLMCapabilityGenerator:
    """Proposes least-privilege capabilities from natural-language policy + task.

    Parameters
    ----------
    llm:
        LLM client for the generator. Must be a distinct instance from the one
        used by LLMVerifierAgent.
    issued_by:
        Identity recorded as the issuer on every proposed capability
        (typically the pipeline or admin identity).
    default_ttl_s:
        Fallback TTL when the LLM omits or zeroes ``ttl_seconds``.
    """

    def __init__(
        self,
        llm: LLMClient,
        issued_by: str,
        *,
        default_ttl_s: float = 3600.0,
    ) -> None:
        self._llm = llm
        self._issued_by = issued_by
        self._default_ttl_s = default_ttl_s

    def propose(
        self,
        *,
        policy: str,
        task: str,
        schema: dict[str, Any],
        agent_id: str,
    ) -> Capability:
        """Ask the LLM to propose a minimal capability for *agent_id*.

        The LLM output is structurally validated; any unrecognised or invalid
        field raises CapabilityGenerationError rather than silently accepting
        bad data.
        """
        user_prompt = (
            f"Policy:\n{policy}\n\n"
            f"Task:\n{task}\n\n"
            f"Data schema:\n{json.dumps(schema, indent=2)}\n\n"
            "Output only the JSON object."
        )
        raw = self._llm.complete(system=_SYSTEM_PROMPT, user=user_prompt, temperature=0.0)
        try:
            spec = _extract_json(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            raise CapabilityGenerationError(
                f"LLM returned unparseable output: {exc}"
            ) from exc

        return self._build(spec, agent_id)

    def _build(self, spec: dict[str, Any], agent_id: str) -> Capability:
        try:
            collection = str(spec["collection"])
            key: str | None = spec.get("key") or None
            ops_raw: list[str] = [str(o) for o in spec.get("operations", [])]
            ttl_raw = spec.get("ttl_seconds")
            ttl_s = float(ttl_raw) if ttl_raw is not None else self._default_ttl_s
        except (KeyError, TypeError, ValueError) as exc:
            raise CapabilityGenerationError(
                f"capability spec has invalid field: {exc}"
            ) from exc

        ops = frozenset(ops_raw) & _VALID_OPS
        if not ops:
            raise CapabilityGenerationError(
                f"no valid operations in LLM output (got {ops_raw!r})"
            )
        if not collection:
            raise CapabilityGenerationError("LLM returned empty collection name")
        if ttl_s <= 0:
            raise CapabilityGenerationError(f"invalid ttl_seconds: {ttl_s}")

        return Capability(
            selector=DataSelector(collection=collection, key=key),
            operations=ops,
            agent_id=agent_id,
            issued_by=self._issued_by,
            not_after=time.time() + ttl_s,
        )
