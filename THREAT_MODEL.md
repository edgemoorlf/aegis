# Aegis Threat Model

> Scope: the data plane, capability broker, LLM generation/verification loop, and
> memory layer as described in PLAN.md. Process sandboxing is explicitly out of scope
> (see PLAN.md §"What This Is Not").

---

## Assets

| Asset | Description | Value |
|---|---|---|
| **Stored records** | Versioned, append-only data in `ImmutableStore` | Primary: the thing being protected |
| **Audit log** | Hash-chained ground-truth record of all actions | Integrity of the entire system |
| **Capability tokens** | Signed grants scoping (data, ops, TTL, agent) | Access control plane |
| **Agent memory** | Derived views with provenance tags | Correctness of agent cognition |
| **Inference context** | Prompts and retrieved data sent to the LLM | Confidentiality + prompt integrity |

---

## Trust Boundary

```
INSIDE (trusted)                  OUTSIDE (untrusted)
─────────────────────────────     ──────────────────────────────────
 ImmutableStore                    Agent processes (any agent)
 AuditLog                          LLM inference process (even local)
 CapabilityBroker (enforcer)        External LLM APIs (explicitly opt-in)
 Signing key material               Human operators (least-privilege)
 SPIFFE/SPIRE identity layer        Retrieved data / user-supplied content
```

Agents are untrusted callers. The data layer grants or denies their requests
based solely on capability tokens — it does not trust any agent's claimed identity
or stated intent.

---

## Threat Actors

| Actor | Capability | Motive |
|---|---|---|
| **Compromised agent** | Has a valid (possibly stolen) capability token | Exfiltrate, corrupt, or escalate |
| **Malicious/buggy agent** | Submits arbitrary requests via the SDK | Destroy data, cause divergence |
| **Adversarial prompt injector** | Can write content into the store that an LLM will later retrieve | Hijack capability generation or verifier decisions |
| **Over-permissioned LLM output** | The capability generator produces a too-broad spec | Unintended access grants |
| **Insider / operator** | Has direct database access or key material | Tamper with audit log, forge tokens |

---

## Threat 1 — Data Exfiltration

**Description.** An agent (compromised, over-trusted, or misbehaving) reads data
it should not have access to and exfiltrates it — either by returning it in a
response, writing it to an external endpoint, or embedding it in a capability
request.

**Attack vectors.**
- Agent holds a broad `READ` capability covering more data than the task requires.
- Agent attenuates a capability but keeps the selector wider than needed.
- External LLM API call leaks context that should have stayed local.

**Mitigations in Aegis.**
- Every `READ` requires a valid, unexpired, unrevoked capability token scoped to
  a specific `DataSelector`. Deny-by-default: no token → no access.
- Attenuation can only narrow; a holder cannot broaden their own token.
- `CapabilityGenerator` proposes minimal-scope tokens; `VerifierAgent` rejects
  or narrows over-permissioned proposals before issuance.
- Local-first inference: context stays inside the trust boundary by default.
  External API calls require explicit allowlisting and appear in the audit log.
- Every `data.read` access is written to the tamper-evident `AuditLog`, enabling
  post-hoc forensics even if exfiltration is detected late.

**Residual risk.** An agent that exfiltrates data via a side channel (e.g., encodes
it in timing, token probabilities, or a writable collection it legitimately holds)
is not blocked at the data-layer level. Network egress controls remain a
complementary defense.

---

## Threat 2 — Prompt Injection via Retrieved Data

**Description.** Adversarial content stored in the `ImmutableStore` is later
retrieved as LLM context and causes the `CapabilityGenerator` or `VerifierAgent`
to emit an over-permissioned capability, approve a malicious action, or deviate
from the stated policy.

**Attack vectors.**
- A record in the store contains instructions that, when concatenated into the
  generator's prompt, override the system policy.
- A memory entry authored by a compromised agent carries injected instructions
  that influence the verifier's next decision.

**Mitigations in Aegis.**
- LLM output is treated as untrusted input throughout: `CapabilityGenerator`
  output is a structured `Capability` object validated against schema before it
  reaches the `VerifierAgent`.
- The `VerifierAgent` runs in a *separate model context* from the generator —
  it receives only the structured `Capability` spec and the authoritative policy,
  not raw retrieved content that could carry injection payloads.
- Every record has provenance (`author`, `version`): retrieved content can be
  tagged and filtered by trust level before being included in an LLM prompt.
- The audit log records which data versions were read, enabling replay analysis
  if an injection is suspected.

**Residual risk.** Prompt injection is an unsolved problem in language models.
Even with structural validation, a sufficiently crafted policy string or schema
description could influence model behavior. A formal/static policy checker as a
backstop to the verifier is noted in Open Questions.

---

## Threat 3 — Cross-Agent Divergence

**Description.** Two or more agents operate on inconsistent views of shared state:
one agent reads a stale version, another writes concurrently, and the system
silently merges or discards one side, producing incorrect downstream behavior.

**Attack vectors.**
- Agent A reads version N; agent B appends version N+1; agent A acts on its
  stale view and appends version N+2 with a conflict.
- A compromised agent deliberately presents an outdated snapshot as current to
  mislead a coordinator agent.
- Agent memory diverges from the audit log (memory was written from a stale or
  incorrect source).

**Mitigations in Aegis.**
- MVCC semantics: every read returns a stamped `Version`. Agents always know which
  version they are acting on; staleness is visible, not hidden.
- Write operations record the `author` and content hash; conflicts are surfaced as
  version gaps, not silently reconciled.
- Agent memory is provenance-tagged `(agent_id, source_data_version, timestamp)`.
  The `MemoryLayer.detect_divergence()` interface compares memory provenance against
  the audit log to identify inconsistencies.
- The audit log is the ground truth: when agents disagree, the authoritative
  record is reconstructed from the log, not negotiated between memories.
- `AuditLog.verify()` detects retroactive tampering with the log itself.

**Residual risk.** Divergence detection (`Phase 4`) is currently an abstract
interface; the concrete divergence algorithm and resolution policy (what to do
once detected) need to be defined. Until Phase 4 lands, cross-agent consistency
is a property of the calling orchestrator, not enforced by Aegis.

---

## Threat 4 — Capability Escalation

**Description.** An agent obtains a capability broader than it is entitled to —
either by exploiting a flaw in the generator/verifier pipeline, forging a token,
replaying an expired token, or coercing a peer agent into re-issuing a token with
wider scope.

**Attack vectors.**
- The `CapabilityGenerator` emits a `DataSelector(collection="*")` or a longer
  `not_after` than the policy permits.
- The `VerifierAgent` is fed a prompt-injected policy that makes it approve a
  wide capability.
- A token is replayed after revocation if the broker's revocation list is stale.
- An agent attenuates a token it received and somehow broadens it (implementation
  defect in `attenuate()`).

**Mitigations in Aegis.**
- `Capability.attenuate()` enforces narrowing invariants at the Python type level:
  - `new_ops <= self.operations` — operations can only shrink.
  - `new_sel.narrows(self.selector)` — selector can only narrow.
  - `min(not_after, self.not_after)` — TTL can only shrink.
  Any broadening raises `ValueError` immediately.
- HMAC signing (`Capability.sign()`) ties a token to its exact payload; any field
  mutation invalidates the signature.
- The broker's `check()` path (Phase 2) verifies signature, expiry, and revocation
  on every access — capability decisions are not cached longer than revocation
  latency allows.
- Every issuance and revocation is written to the `AuditLog`. An unusually broad
  or repeated issuance is detectable in post-hoc audit.
- The `VerifierAgent` runs in a separate model context specifically to prevent the
  generator from self-approving a broad capability.

**Residual risk.** The HMAC signing in v0.1.0 uses a shared secret. A compromised
secret allows arbitrary token forgery. Migration to asymmetric keys (biscuit/
macaroon tokens) is noted as a Phase 2 upgrade; until then, key material must be
treated as high-value infrastructure secret.

---

## Threat 5 — Audit Log Tampering

**Description.** An insider or compromised privileged process modifies or deletes
audit log entries to cover tracks or manufacture a false history.

**Attack vectors.**
- Direct SQL `UPDATE`/`DELETE` on the `audit` table by a privileged DB user.
- Truncation or rotation of the underlying SQLite file.
- Replay of a previous database snapshot to make recent events disappear.

**Mitigations in Aegis.**
- The `AuditLog` Python API exposes no `update` or `delete` methods. The agent
  interface is write-only: `append()` and read (`entries()`, `verify()`).
- SHA-256 hash chain: every entry commits to `prev_hash`. Any edit or deletion
  breaks the chain and is immediately detectable by `AuditLog.verify()`.
- The `CLAUDE.md` architecture invariant explicitly forbids `UPDATE`/`DELETE` on
  the `audit` table in any code path.

**Residual risk.** A determined insider with direct database access can replace
the entire file (including recomputing a fresh chain) and defeat the in-process
chain check. A Merkle-tree / transparency-log upgrade (Trillian-style) with an
external witness is noted in the roadmap for v2. Until then, the audit log should
be periodically checkpointed and the checkpoint hash stored out-of-band (e.g.,
in a separate append-only object store, a notary, or a git commit).

---

## Summary Table

| Threat | Primary control | Residual risk |
|---|---|---|
| Data exfiltration | Capability tokens + deny-by-default | Side-channel exfiltration; network egress |
| Prompt injection | Separate verifier context; structured output validation | Unsolved at model level; no formal backstop yet |
| Cross-agent divergence | MVCC versioning; provenance-tagged memory; audit log as ground truth | Concrete divergence detection (Phase 4) not yet implemented |
| Capability escalation | Attenuation invariants; HMAC signing; revocation; dual-context verifier | Shared HMAC secret; asymmetric upgrade pending |
| Audit log tampering | Hash chain + insert-only schema + no-delete invariant | Full-file replacement; transparency-log upgrade pending |

---

## Out of Scope (v1)

- **Process sandbox / code execution integrity.** A seccomp + namespace sandbox
  is a reasonable last-mile residual for locally-executed code, but is explicitly
  not a primary defense and is out of scope for v1.
- **Network egress control.** Blocking exfiltration channels requires a network
  policy layer outside Aegis.
- **LLM model integrity.** Adversarial fine-tuning or weight poisoning of the
  local inference model is assumed to be a supply-chain concern addressed upstream.
- **Physical / VM-level attacks.** Hardware-level attacks on the host running
  the store or broker are out of scope.
