"""End-to-end capability pipeline: NL policy → generate → verify → issue (Phase 3).

Ties together the generator, verifier, and broker into a single audited flow:

  1. LLMCapabilityGenerator proposes a capability from natural-language inputs.
  2. LLMVerifierAgent (separate model context) audits the proposal.
  3. If approved → broker.issue() returns a signed token.
  4. If rejected with a narrowing → re-verify the narrowed capability (skip regeneration).
  5. If rejected without narrowing, or after max_rounds → raise PipelineError.

Every round is written to the AuditLog so the full provenance of each issued
token (which policy, which task, how many rounds, what narrowings were applied)
is permanently queryable.
"""

from __future__ import annotations

from typing import Any

from .audit import AuditLog
from .broker import CapabilityBroker
from .capability import Capability
from .generator import LLMCapabilityGenerator
from .verifier import LLMVerifierAgent, Verdict

_DEFAULT_MAX_ROUNDS: int = 3


class PipelineError(RuntimeError):
    """Raised when the pipeline cannot produce an approved, issued capability."""


class CapabilityPipeline:
    """Orchestrates the generate → verify → issue loop.

    Parameters
    ----------
    generator:
        LLMCapabilityGenerator instance.
    verifier:
        LLMVerifierAgent instance. MUST use a different LLMClient than the
        generator (separate model context — see THREAT_MODEL.md §Threat 2).
    broker:
        CapabilityBroker for final issuance.
    audit_log:
        AuditLog where every pipeline round is recorded.
    max_rounds:
        Maximum generate-verify iterations before raising PipelineError.
    """

    def __init__(
        self,
        generator: LLMCapabilityGenerator,
        verifier: LLMVerifierAgent,
        broker: CapabilityBroker,
        audit_log: AuditLog,
        *,
        max_rounds: int = _DEFAULT_MAX_ROUNDS,
    ) -> None:
        if generator._llm is verifier._llm:
            raise ValueError(
                "generator and verifier must use separate LLMClient instances "
                "(same instance violates the separate-context requirement)"
            )
        self._generator = generator
        self._verifier = verifier
        self._broker = broker
        self._audit = audit_log
        self._max_rounds = max_rounds

    def issue(
        self,
        *,
        agent_id: str,
        policy: str,
        task: str,
        schema: dict[str, Any],
    ) -> str:
        """Run the full NL-policy pipeline and return an issued capability token.

        Raises PipelineError if the verifier rejects all proposals within
        max_rounds, or rejects without providing a narrowing.
        """
        cap: Capability = self._generator.propose(
            policy=policy, task=task, schema=schema, agent_id=agent_id
        )
        self._audit.append(
            "pipeline",
            "capability.generate",
            agent_id,
            details=self._cap_summary(cap, round_num=1),
        )

        for round_num in range(1, self._max_rounds + 1):
            verdict: Verdict = self._verifier.review(cap, policy=policy)
            self._audit.append(
                "pipeline",
                "capability.verify",
                agent_id,
                capability_id=cap.capability_id,
                details={
                    "round": round_num,
                    "approved": verdict.approved,
                    "reason": verdict.reason,
                    "narrowed": verdict.narrowed is not None,
                },
            )

            if verdict.approved:
                return self._broker.issue(cap)

            if verdict.narrowed is None:
                raise PipelineError(
                    f"verifier rejected without providing a narrowing "
                    f"(round {round_num}/{self._max_rounds}): {verdict.reason}"
                )

            cap = verdict.narrowed
            self._audit.append(
                "pipeline",
                "capability.generate",
                agent_id,
                details=self._cap_summary(cap, round_num=round_num + 1, narrowed=True),
            )

        raise PipelineError(
            f"capability not approved after {self._max_rounds} rounds; "
            f"last rejection: {verdict.reason}"
        )

    @staticmethod
    def _cap_summary(
        cap: Capability, *, round_num: int, narrowed: bool = False
    ) -> dict[str, Any]:
        return {
            "round": round_num,
            "collection": cap.selector.collection,
            "key": cap.selector.key,
            "operations": sorted(cap.operations),
            "not_after": cap.not_after,
            "narrowed_from_previous": narrowed,
        }
