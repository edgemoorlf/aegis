"""End-to-end demo: data-layer containment + ground-truth recovery.

Scenario (the Phase 5 idea, in miniature on the Phase 1 foundation):

  - Three agents operate on a shared ImmutableStore.
  - A buggy/malicious agent "deletes" a record. Because deletion is a logical
    tombstone, the data is NOT lost — prior versions remain readable.
  - Two agents end up with divergent views of a record. We do NOT mediate
    between their memories; we reconstruct ground truth from the AuditLog.

Run:  python -m examples.multi_agent_demo   (from the repo root, after install)
or:   python examples/multi_agent_demo.py
"""

from __future__ import annotations

from aegis import AuditLog, ImmutableStore


def main() -> None:
    store = ImmutableStore()
    audit = AuditLog()

    def write(agent: str, key: str, value: dict) -> None:
        v = store.append("ledger", key, value, author=agent)
        audit.append(agent, "data.append", f"ledger/{key}",
                     details={"version": v.version, "content_hash": v.content_hash})

    def read(agent: str, key: str) -> dict:
        v = store.read("ledger", key)
        audit.append(agent, "data.read", f"ledger/{key}",
                     details={"version": v.version})
        return v.value

    print("=== 1. Agents collaborate on a shared record ===")
    write("planner", "balance", {"amount": 100})
    write("executor", "balance", {"amount": 80})   # spent 20
    print("current balance:", read("auditor", "balance"))

    print("\n=== 2. A misbehaving agent 'deletes' the record ===")
    store.tombstone("ledger", "balance", author="rogue")
    audit.append("rogue", "data.tombstone", "ledger/balance")
    try:
        store.read("ledger", "balance")
    except Exception as e:
        print("latest view:", type(e).__name__, "-", e)

    print("--> data is NOT lost; never-delete preserves history:")
    for v in store.history("ledger", "balance"):
        tag = "TOMBSTONE" if v.is_tombstone else v.value
        print(f"    v{v.version} by {v.author}: {tag}")

    print("\n=== 3. Divergent agent views; reconstruct ground truth from audit ===")
    # Imagine planner's memory still says 100 and executor's says 80.
    planner_belief = {"amount": 100}
    executor_belief = {"amount": 80}
    print("planner believes:", planner_belief)
    print("executor believes:", executor_belief)

    # Ground truth is not negotiated between memories — it is the audit log.
    appends = audit.entries(action="data.append", target="ledger/balance")
    latest = max(appends, key=lambda e: e.details["version"])
    truth_version = latest.details["version"]
    truth_value = store.read("ledger", "balance", as_of_version=truth_version).value
    print(f"audit-derived ground truth: v{truth_version} = {truth_value} "
          f"(written by {latest.actor})")

    print("\n=== 4. The audit chain is tamper-evident ===")
    print("chain verifies:", audit.verify())

    store.close()
    audit.close()


if __name__ == "__main__":
    main()
