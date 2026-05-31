"""LLM-backed VerifierAgent (Phase 3).

The verifier is an independent critic that audits a proposed capability for
over-permissioning, least-privilege violations, and policy contradictions.

Critical: the verifier MUST use a separate LLMClient instance from the
generator. Sharing a client would mean both sides of the critique run in the
same model context, enabling the model to rationalise its own proposals
(self-justification). See PLAN.md §Design Principles and THREAT_MODEL.md §Threat 2.

Verdicts are structured: approved (bool), reason (str), and an optional
narrowed Capability. If the verifier rejects but can propose a narrowing, the
pipeline can re-verify the narrowed capability without re-running the generator.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Optional

from .capability import APPEND, READ, TOMBSTONE, Capability, DataSelector
from .llm import LLMClient

_VALID_OPS: frozenset[str] = frozenset({READ, APPEND, TOMBSTONE})

_SYSTEM_PROMPT = """\
You are an independent security auditor reviewing a proposed capability specification.
Your role is to enforce the principle of least privilege and policy compliance.
Be stricter than the generator: err on the side of narrowing.

Checks to perform:
1. Does the capability grant operations not explicitly required by the policy?
2. Is the data selector (collection + key) broader than the task requires?
3. Is the TTL longer than necessary for the task?
4. Does the capability contradict or exceed the stated policy?

Output a single JSON object with no other text:
{
  "approved": true | false,
  "reason": "<one sentence explanation>",
  "narrowed": {
    "operations": [...],
    "key": "<specific key or null>",
    "ttl_seconds": <positive integer>
  } | null
}

Rules for the "narrowed" field:
- Set it only when you reject AND can propose a valid narrowing.
- Narrowing must strictly reduce scope: fewer ops, tighter key, or shorter TTL.
- Omit any field you are not changing.
- If the capability fundamentally violates the policy (e.g. wrong collection),
  set "narrowed" to null — a narrowing cannot fix a wrong collection.
- If you approve, set "narrowed" to null.
"""


class VerificationError(ValueError):
    """Raised when the verifier LLM returns an unusable response."""


@dataclass(frozen=True)
class Verdict:
    """Outcome of a verifier review. Satisfies VerdictProtocol from broker.py."""

    approved: bool
    reason: str
    narrowed: Optional[Capability] = None


def _extract_json(text: str) -> dict[str, Any]:
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
        raise ValueError(f"no JSON object found in verifier output: {text!r}")


class LLMVerifierAgent:
    """Reviews a proposed capability and returns a Verdict.

    Must be constructed with a DIFFERENT LLMClient instance than the generator
    to satisfy the separate-context requirement.
    """

    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    def review(self, proposed: Capability, *, policy: str) -> Verdict:
        """Audit *proposed* against *policy*. Returns a Verdict.

        If the verifier proposes a narrowing, the returned Verdict carries a
        new Capability that is strictly no broader than *proposed* (attenuation
        invariants are re-enforced here, not trusted from the LLM).
        """
        cap_json = json.dumps(
            {
                "collection": proposed.selector.collection,
                "key": proposed.selector.key,
                "operations": sorted(proposed.operations),
                "ttl_seconds": max(0.0, proposed.not_after - time.time()),
                "agent_id": proposed.agent_id,
            },
            indent=2,
        )
        user_prompt = (
            f"Policy:\n{policy}\n\n"
            f"Proposed capability:\n{cap_json}\n\n"
            "Review for least-privilege compliance. Output only the JSON verdict."
        )
        raw = self._llm.complete(system=_SYSTEM_PROMPT, user=user_prompt, temperature=0.0)
        try:
            verdict_raw = _extract_json(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            raise VerificationError(
                f"verifier returned unparseable output: {exc}"
            ) from exc

        try:
            approved = bool(verdict_raw["approved"])
            reason = str(verdict_raw.get("reason", ""))
        except KeyError as exc:
            raise VerificationError(
                f"verifier response missing required field: {exc}"
            ) from exc

        narrowed: Optional[Capability] = None
        narrowed_raw = verdict_raw.get("narrowed")
        if narrowed_raw and isinstance(narrowed_raw, dict):
            narrowed = self._apply_narrowing(proposed, narrowed_raw)

        return Verdict(approved=approved, reason=reason, narrowed=narrowed)

    @staticmethod
    def _apply_narrowing(
        base: Capability, spec: dict[str, Any]
    ) -> Capability:
        """Derive a narrowed capability from the verifier's spec.

        All attenuation invariants are re-enforced here. Any broadening in the
        verifier's output is silently clamped back to the base capability.
        """
        # Operations: intersect with base (never add)
        new_ops: Optional[frozenset[str]] = None
        if "operations" in spec:
            raw_ops = frozenset(str(o) for o in spec["operations"]) & _VALID_OPS
            new_ops = raw_ops & base.operations  # cannot add ops
            if not new_ops:
                new_ops = base.operations  # degenerate: keep base rather than empty

        # Selector: key can only narrow (whole-collection → specific key), never broaden
        new_selector: Optional[DataSelector] = None
        if "key" in spec:
            proposed_key: Optional[str] = spec["key"] or None
            if base.selector.key is None and proposed_key is not None:
                new_selector = DataSelector(
                    collection=base.selector.collection, key=proposed_key
                )
            # If base already has a specific key, we keep it (verifier cannot change it)

        # TTL: take the minimum
        new_not_after: Optional[float] = None
        if "ttl_seconds" in spec:
            try:
                ttl_s = float(spec["ttl_seconds"])
                if ttl_s > 0:
                    new_not_after = min(base.not_after, time.time() + ttl_s)
            except (TypeError, ValueError):
                pass

        return base.attenuate(
            operations=new_ops,
            selector=new_selector,
            not_after=new_not_after,
        )
