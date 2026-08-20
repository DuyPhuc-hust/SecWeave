"""Cost Service — SPEC P6 ("Chi phí và phạm vi tác động phải có trần") and
§6.4 control #9 ("Không vượt hard cost cap"). Two distinct checks live here,
matching two distinct moments in the pipeline — approval at one does NOT
imply the other:

- check_planned_action_cap(): a PLANNING-time gate (weekly plan W5) — counts
  actions already listed in an ActionPlan, BEFORE any of them has ever
  executed, so an over-sized plan is refused before Gate 3 release even
  considers it.
- CostService: the RUNTIME gate (weekly plan Tuần 6) — counts actions
  ACTUALLY executed via EvidenceHarness.capture() during one active run,
  and automatically triggers the kill-switch (source=AUTOMATIC_THRESHOLD,
  automatic_threshold_reason=ACTION_COUNT_EXCEEDED) the moment the NEXT
  action would exceed cap — refusing that action itself (never sending it)
  rather than stopping only after the fact.

check_planned_action_cap() approving a plan does not mean CostService will
let it fully execute: the plan's declared action count could drift from
what actually gets attempted (e.g. a retried action, or a caller reusing
one execution_id across more than one plan), or the Execution Release's
frozen runtime cap could simply be tighter than the plan-time one.
CostService is the real enforcement point; check_planned_action_cap is an
earlier, cheaper sanity check that cannot substitute for it.
"""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from shared.models.action import ActionPlan, CostDecision, RuntimeCostDecision


def check_planned_action_cap(plan: ActionPlan, cap: int) -> CostDecision:
    """Cost Service (skeleton) — weekly plan W5: "count the planned actions in
    the plan against a cap (only planned actions for now, actual executed
    actions come the following week)".

    Counting REAL executed actions (not just planned ones) is the job of the
    week that adds Evidence Harness — this function does not replace the
    runtime cost-cap control (see CostService below, now that week has come).
    """
    count = len(plan.actions)
    if count > cap:
        return CostDecision(
            allowed=False,
            reason=f"Kế hoạch có {count} hành động dự kiến, vượt cap cho phép ({cap}).",
            planned_action_count=count,
            cap=cap,
        )
    return CostDecision(
        allowed=True,
        reason=f"Kế hoạch có {count} hành động dự kiến, trong cap cho phép ({cap}).",
        planned_action_count=count,
        cap=cap,
    )


class CostCapExceededError(RuntimeError):
    """Raised by EvidenceHarness.capture() (or any other real-execution call
    site wired to a CostService) instead of sending a real request once the
    NEXT action would exceed the runtime cost cap — mirrors
    ExecutionStoppedError's role for the kill-switch (shared/kill_switch.py),
    but for SPEC §6.4 control #9 ("không vượt hard cost cap") rather than an
    explicit human/other-automatic stop.
    """


class CostService:
    """One instance = one execution context (same convention as
    EvidenceHarness/KillSwitch: execution_id is fixed for the whole run).
    Construct once per execution_id and share the SAME instance with
    EvidenceHarness (pass as `cost_service=` to its constructor) so every
    real capture() attempt is counted against the same running total.

    Persists an append-only JSONL log (one line per action actually
    recorded) under `{storage_dir}/{execution_id}/cost_audit_log.jsonl` —
    `__init__` recovers the running count from this log, so a process
    restart mid-run does NOT reset the count to 0 and silently let a capped
    run exceed its true total across the restart (same crash-recovery
    reasoning as KillSwitch's own audit log — see shared/kill_switch.py).

    Unlike KillSwitch.stop(), there is no arbitrary, possibly-slow user-
    supplied callback here (no `cleanup`-equivalent), so the log append
    happens INSIDE the same lock as the check-and-increment rather than
    split across a lock/no-lock boundary the way KillSwitch's `sequence`
    trick requires — nothing here can make one caller's write land out of
    true logical order, so that whole class of bug does not apply.

    Scope boundary: same cross-instance limitation as KillSwitch (see its
    own docstring) — two CostService instances can each recover the same
    count, both see `count < cap`, and both record an action, jointly
    exceeding cap by more than 1. Every call site here constructs exactly
    one CostService per execution_id within a single process.
    """

    def __init__(self, execution_id: str, storage_dir: str, cap: int) -> None:
        self._execution_id = execution_id
        self._cap = cap
        self._storage_dir = Path(storage_dir) / execution_id
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._audit_log_path = self._storage_dir / "cost_audit_log.jsonl"
        self._lock = threading.Lock()
        self._count, recorded_cap = self._recover_count_from_audit_log()
        # `cap` itself is cross-checked, not just the executed-action
        # COUNT — a later invocation reusing the same execution_id (the
        # intended way cost accumulates "real meaning" across cmd_execute
        # calls) must not be able to pass a DIFFERENT --cap and get a
        # widened effective budget, which would undermine SPEC §6.4
        # control #9's "never exceed the hard cap" as a durable per-
        # execution property. Fails safe/closed: refuses to proceed rather
        # than silently pick either value. A log with no recorded cap yet
        # (first run) has nothing to conflict with, so it's accepted.
        if recorded_cap is not None and recorded_cap != cap:
            raise RuntimeError(
                f"CostService cho execution '{execution_id}': cap trước đó đã ghi nhận là "
                f"{recorded_cap}, nhưng lần khởi tạo này truyền cap={cap} — không cho phép đổi cap "
                "giữa chừng cho cùng 1 execution_id. Dùng execution_id mới nếu thực sự cần cap khác."
            )

    def _recover_count_from_audit_log(self):
        if not self._audit_log_path.exists():
            return 0, None
        lines = self._audit_log_path.read_text(encoding="utf-8").splitlines()
        count = 0
        recorded_cap = None
        for line in lines:
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                # A crash mid-write can only tear the LAST line (normal
                # appends are a single atomic write() — see record_action()).
                # Fail safe for a cost cap means assuming the worst: this
                # attempted action DID consume real budget, not that it
                # silently didn't happen. Undercounting here is exactly the
                # kind of gap that would let a restart quietly exceed the
                # true cap — same "fail safe = assume the worst" reasoning
                # as KillSwitch's own corrupted-line recovery, just applied
                # to a counter (count it) rather than a status (assume
                # STOPPED).
                entry = None
            if entry is not None and "cap" in entry:
                recorded_cap = entry["cap"]
            count += 1
        return count, recorded_cap

    @property
    def cap(self) -> int:
        return self._cap

    @property
    def executed_action_count(self) -> int:
        with self._lock:
            return self._count

    def _ends_without_trailing_newline(self) -> bool:
        """True if the audit log file exists, is non-empty, and its last
        byte is NOT a newline — a crash mid-write tears only the LAST line
        (see _recover_count_from_audit_log's docstring), and a plain
        append afterward would otherwise concatenate the NEXT entry
        directly onto that torn line's tail with no separator, merging one
        perfectly valid, recoverable entry into what recovery then sees as
        a SINGLE unparseable line — permanently losing that valid entry
        from the count (recovery only ever credits a corrupted line +1,
        never +2), undercounting the true total across a SECOND restart.
        Checked via a raw byte read of just the last byte, not text-mode
        `tell()` semantics (ambiguous in append mode).
        """
        if not self._audit_log_path.exists():
            return False
        size = self._audit_log_path.stat().st_size
        if size == 0:
            return False
        with open(self._audit_log_path, "rb") as f:
            f.seek(-1, os.SEEK_END)
            last_byte = f.read(1)
        return last_byte != b"\n"

    def record_action(self, action_ref: str) -> RuntimeCostDecision:
        """Call exactly once per real EvidenceHarness.capture() ATTEMPT,
        BEFORE the actual HTTP request is sent — success or failure at the
        HTTP level doesn't matter, an attempted action already consumed
        real budget against the target (SPEC P2: an attempt is evidence
        either way). Returns allowed=False WITHOUT recording anything if
        this action would push the count past cap — refuses the action
        BEFORE the cap is actually exceeded, never after.

        Raises RuntimeError (wrapping the underlying OSError) if the
        durable log write itself fails (disk full, permission lost, etc.)
        — the in-memory count is NOT advanced in that case. Incrementing
        `self._count` BEFORE the write would otherwise leave the in-memory
        count permanently ahead of what was actually persisted if the
        write then failed, for the rest of this process's life (a later
        restart would recover the LOWER, correct value, silently diverging
        from what this process believed). The durable write must succeed
        FIRST; only then does the in-memory count move to match it.
        """
        with self._lock:
            current = self._count
            allowed = current < self._cap
            if allowed:
                new_count = current + 1
                entry = {
                    "action_ref": action_ref,
                    "sequence": new_count,
                    "at": datetime.now(timezone.utc).isoformat(),
                    "cap": self._cap,
                }
                line = json.dumps(entry) + "\n"
                try:
                    needs_leading_newline = self._ends_without_trailing_newline()
                    with open(self._audit_log_path, "a", encoding="utf-8") as f:
                        if needs_leading_newline:
                            f.write("\n")
                        f.write(line)
                except OSError as exc:
                    raise RuntimeError(
                        f"CostService cho execution '{self._execution_id}': không ghi được "
                        f"cost_audit_log cho action '{action_ref}' — {type(exc).__name__}: {exc}. "
                        "Count trong bộ nhớ KHÔNG tăng vì chưa chắc đã ghi bền vững xuống đĩa."
                    ) from exc
                self._count = new_count
                reason = (
                    f"Hành động '{action_ref}' được ghi nhận — {self._count}/{self._cap} hành động "
                    "thực tế đã thực thi cho execution này."
                )
            else:
                reason = (
                    f"Đã đạt cost cap: {current}/{self._cap} hành động thực tế đã thực thi — hành "
                    f"động '{action_ref}' bị TỪ CHỐI, không thực thi."
                )
            return RuntimeCostDecision(
                allowed=allowed,
                reason=reason,
                executed_action_count=current,
                cap=self._cap,
            )
