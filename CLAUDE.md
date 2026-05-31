# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this is

Aegis is a **data-centric, capability-based substrate for multi-agent systems**.
The thesis: *protect the data, not the sandbox.* Compute is assumed untrusted and
transient; the data layer is the security and consistency boundary.

Read `PLAN.md` for the full architecture and roadmap before making structural
changes. Read `README.md` for the user-facing summary.

## Architecture invariants (do not violate)

These are the core design commitments. Treat them as constraints, not suggestions:

1. **Never delete.** The store is append-only and versioned. Nothing is ever
   overwritten or hard-deleted. "Deletion" is a logical tombstone (a new version).
   No code path may issue SQL `UPDATE` or `DELETE` against `records` or `audit`.
2. **The audit log is ground truth.** Agent memories are derived views, never the
   source of truth. Cross-agent discrepancies are resolved against the log.
3. **Tamper-evidence is mandatory.** The audit chain must stay verifiable. Any
   change to entry fields must be reflected in `compute_entry_hash`'s payload.
4. **Capabilities only narrow.** Attenuation may never broaden operations, widen a
   selector, or extend a TTL. Enforcement is deny-by-default.
5. **Local-first inference.** When Phase 3 lands, the LLM runs inside the trust
   boundary by default. External APIs are an explicitly allowlisted, audited
   exception — never the silent default.

If a requested change conflicts with one of these, stop and flag it rather than
quietly working around it.

## Project layout

```
src/aegis/
  store.py        # Phase 1: ImmutableStore (append-only, versioned, time-travel)
  audit.py        # Phase 1: AuditLog (hash-chained, tamper-evident)
  capability.py   # Phase 2 foundation: Capability schema + attenuation + signing
  broker.py       # Phase 2-4 interfaces (abstract; raise NotImplementedError)
  __init__.py     # public API surface
tests/            # pytest, mirrors src module names
examples/         # runnable demos
```

## Commands

```bash
uv sync --extra dev         # set up venv and install all dev dependencies
uv run pytest               # run tests (must pass before any commit)
uv run ruff check src tests # lint (must be clean)
uv run mypy                 # strict type check (must be clean)
uv run python examples/multi_agent_demo.py   # end-to-end smoke demo
```

The full gate before committing: **pytest green, ruff clean, mypy clean.**

## Conventions

- Python 3.11+; full type hints; `mypy --strict` must pass.
- Public API changes go through `src/aegis/__init__.py` and are reflected in README.
- Every new feature ships with tests in the matching `tests/test_<module>.py`.
- Storage tables stay insert-only. Add columns/tables rather than mutating rows.
- JSON serialization for hashing uses the canonical encoder (`sort_keys`,
  compact separators) so content/entry hashes stay stable. Reuse the existing
  `_canonical` helpers; don't introduce a second encoding.
- Keep dependencies minimal. v1 has zero runtime deps by design; justify any
  addition in the PR description.
- Commit messages use Conventional Commits (`feat:`, `fix:`, `chore:`, `test:`,
  `docs:`), scoped where useful (`feat(store): ...`).

## Roadmap context (what's next)

Phase 1 (store + audit) is implemented. The likely next units of work:

- **Phase 2 — CapabilityBroker:** real issuance / revocation / TTL + deny-by-default
  enforcement, with **every decision written to the AuditLog**. Implement against
  the `CapabilityBroker` ABC in `broker.py`.
- **Phase 3 — LLM generation + verifier loop:** `CapabilityGenerator` and
  `VerifierAgent`. The verifier must run in a *separate* model context from the
  generator. Local model behind a stable interface.
- **Phase 4 — MemoryLayer:** provenance-tagged memory + divergence detection
  against the audit log.

When implementing an interface from `broker.py`, keep the abstract signature
stable; if it must change, update the ABC, all implementations, and the README
status table together.

## Things to avoid

- Don't reintroduce execution-sandboxing as a *primary* defense — it's explicitly
  the wrong layer for this project (see PLAN.md "What This Is Not"). A lightweight
  process sandbox is at most a documented last-mile residual, out of scope for now.
- Don't let an agent's memory become authoritative over the audit log.
- Don't add hidden network calls. Anything that leaves the machine is opt-in and
  auditable.
