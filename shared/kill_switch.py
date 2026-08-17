"""Kill-switch — SPEC §6.3 ("năm nguồn người + một ngưỡng tự động") and §5.3
("đường dừng khẩn"): any of 5 human sources or 1 automatic threshold can stop
a RUNNING execution immediately, no negotiation required ("không cần thương
lượng trước"). After a stop: an approved cleanup runs, and everything is
logged (SPEC: "reset/cleanup đã duyệt tại Gate 3 được thực hiện, có ghi
log"). Weekly plan Tuần 6: "một lệnh/API dừng được execution đang RUNNING ->
chuyển STOPPED, trigger cleanup đã duyệt, ghi audit log — gọi được từ >= 5
vai trò khác nhau."

Design decisions NOT dictated by SPEC (checked against real-world prior art
before building this — see the design discussion this was built from) —
flagged here so a future reviewer knows what to scrutinize:

- stop() performs NO permission check on `source`/`actor`. This matches
  SPEC's own "không cần thương lượng trước" AND the real-world precedent
  this design was checked against: FINRA Rule 15c3-5 / SEC Market Access
  Rule kill switches for algorithmic trading, where multiple independent
  parties can each trigger a halt without the others' agreement. Whoever is
  allowed to hold a reference to this object (or call whatever future
  CLI/API wraps it) is a question for that wrapping layer, not this class.

- No auto-resume, no timer, no half-open retry of any kind. Checked
  specifically against the circuit-breaker pattern to avoid copying its
  defining feature by accident: a circuit breaker re-tries automatically
  after a cooldown; a kill switch requires an explicit human decision to
  resume. SPEC §6.4 control #10 ("không tiếp tục sau stop-work trigger nếu
  chưa được cho phép chạy lại") requires exactly this — resume() is the ONLY
  way back to RUNNING, and nothing in this class calls it on its own.

- The integration point in evidence_harness/harness.py's capture() only
  checks `is_stopped` before sending a request ("cooperative cancellation" —
  the same pattern workflow engines like Temporal use for running tasks). It
  does NOT forcibly abort an in-flight HTTP request. A single HTTP call has
  a bounded timeout and finishes on its own; industry guidance reserves hard
  "terminate" for tasks that are stuck and can't be cancelled cooperatively,
  which doesn't describe this case. Consequence, stated plainly: a request
  that started sending in the instant before stop() completes can still
  land — no software kill switch (including the trading ones above) closes
  that window to zero.

- The audit log is local-disk JSON Lines, never a call to the target or any
  other external service — a kill switch must not depend on the same
  infrastructure it might need to act against being reachable/healthy.

- Every audit-log entry carries a `sequence` number, assigned atomically
  under `self._lock` at the moment of the real status transition — NOT the
  same thing as physical file-append order. Real bug found via a second
  independent review pass, after the first review's fix for the "slow
  cleanup blocks other callers" problem (see stop()'s docstring) moved the
  audit-log WRITE outside the lock: since a STOP's write only happens after
  its (possibly slow) cleanup finishes, a concurrent RESUME on another
  thread can have its write land in the file FIRST even though the STOP's
  real transition happened first — so physical last-line-in-file is not a
  safe proxy for "what happened last." `sequence` fixes this by being
  assigned at transition time (fast, under the lock), decoupled from
  whenever the slow I/O for that entry actually happens to complete; status
  recovery (_recover_status_from_audit_log) picks the entry with the
  MAX `sequence`, never just the physically-last line.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from shared.models.kill_switch import (
    AuditEventType,
    AutomaticThresholdReason,
    CleanupStatus,
    ExecutionStatus,
    StopEvent,
    StopSource,
)

__all__ = [
    "AuditEventType",
    "AutomaticThresholdReason",
    "CleanupStatus",
    "ExecutionStatus",
    "ExecutionStoppedError",
    "KillSwitch",
    "StopEvent",
    "StopSource",
]


class ExecutionStoppedError(RuntimeError):
    """Raised by EvidenceHarness.capture() (or any other real-execution call
    site wired to a KillSwitch) instead of sending a real request once
    is_stopped is True. Deliberately a hard raise, not a special return value
    a caller loop could accidentally ignore and continue past — SPEC: "Agent
    hoặc model không có quyền từ chối lệnh dừng"."""


class KillSwitch:
    """One instance = one execution context (same convention as
    EvidenceHarness: execution_id is fixed for the whole run). Construct
    once per execution_id and share the SAME instance with EvidenceHarness
    (and, later, any Cost Service / Execute loop) so all of them observe the
    same RUNNING/STOPPED state within one process.

    Scope boundary, stated plainly: `__init__` reconstructs status from the
    on-disk audit log so a NEW instance correctly picks up a PRIOR instance's
    last known state (e.g. after a crash/restart — see
    _recover_status_from_audit_log). That handles SEQUENTIAL reconstruction
    only. It does NOT make it safe for multiple instances to be alive and
    mutating state AT THE SAME TIME — `self._lock` is a plain in-process
    `threading.Lock`, so it provides mutual exclusion only between calls made
    through the SAME instance, never across two different instances (even in
    the same process, let alone two OS processes both pointed at the same
    storage_dir). Every call site in this codebase constructs exactly one
    KillSwitch per execution_id within a single process, matching this
    constraint; true cross-process concurrent safety (e.g. an OS-level file
    lock, or an external coordination store) is a bigger mechanism this MVP
    increment does not attempt.
    """

    def __init__(
        self,
        execution_id: str,
        storage_dir: str,
        cleanup: Optional[Callable[[], None]] = None,
    ) -> None:
        """`cleanup` is "reset/cleanup đã duyệt tại Gate 3" — since no real
        Gate 3 process exists yet in Chặng 1, this is a plain callable the
        operator/caller supplies at construction (same "gates assumed
        approved, operator-supplied" pattern as allowlists and credentials
        elsewhere in this codebase). A common real shape: pass a bound
        EvidenceHarness.close (closes every identity's session/cookie jar) —
        the software equivalent of a trading kill switch not just blocking
        new orders but also unwinding ones already open.
        """
        self._execution_id = execution_id
        self._storage_dir = Path(storage_dir) / execution_id
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._audit_log_path = self._storage_dir / "kill_switch_audit_log.jsonl"
        self._cleanup = cleanup
        self._lock = threading.Lock()
        # Real gap found via independent review: this used to hardcode
        # PREPARED unconditionally, ignoring any audit log already on disk
        # for this execution_id — so simply constructing a SECOND KillSwitch
        # instance for an execution that was already STOPPED (a crash
        # recovery, a separate CLI/API process, a worker restart — all
        # explicitly anticipated by read_audit_log()'s own docstring) would
        # silently reset it to PREPARED, letting start() succeed with zero
        # record of authorization. Status is now derived from the audit
        # log's last (by `sequence`, not file position — see module
        # docstring) event, instead of always assuming "brand new".
        self._status, self._sequence = self._recover_from_audit_log()

    def _recover_from_audit_log(self) -> Tuple[ExecutionStatus, int]:
        entries, had_corrupt_line = self._read_audit_log_raw()
        if had_corrupt_line:
            # A line can only be corrupt if a crash interrupted a write
            # mid-line (normal appends are atomic — see _append_audit_log).
            # That's exactly a scenario this recovery path exists to handle,
            # so we can't just trust whatever partial history IS parseable.
            # Fail SAFE for a kill switch means assume the worst: STOPPED,
            # not PREPARED/RUNNING — an operator has to look and explicitly
            # resume(), rather than the execution silently continuing on an
            # unverifiable audit trail. `sequence` still needs to keep
            # counting up past whatever we could parse, so a legitimate
            # entry logged after this doesn't collide with an old one.
            max_sequence = max((e.get("sequence", 0) for e in entries), default=0)
            return ExecutionStatus.STOPPED, max_sequence
        if not entries:
            return ExecutionStatus.PREPARED, 0
        max_sequence = max(e["sequence"] for e in entries)
        tied = [e for e in entries if e["sequence"] == max_sequence]
        if len(tied) > 1:
            # Real gap found via independent review: `sequence` is a LOCAL
            # counter per instance, recovered from "current max in the log"
            # at construction/refresh() time — it is NOT a globally unique
            # counter shared across instances. Two DIFFERENT KillSwitch
            # instances (e.g. this process's own instance auto-stopping via
            # CostService, racing an independent `secweave kill` CLI
            # invocation pointed at the same execution_id/storage_dir) can
            # each recover the SAME "last known sequence" before either has
            # written its own next event, and independently compute the
            # SAME next value — the exact ambiguity `sequence` was invented
            # to eliminate, just recurring one layer up (at assignment time
            # across instances, not just at write time within one). Picking
            # via `max(entries, key=...)` in that case silently broke the
            # tie by PHYSICAL FILE ORDER (Python's max() keeps the first-
            # seen maximal element) — correlated with nothing meaningful.
            # Fail safe the same way a corrupted line already does: treat a
            # genuine sequence tie as an unresolvable ambiguity and assume
            # the worst, STOPPED — a kill switch must never silently prefer
            # RUNNING when it cannot actually tell which transition is real.
            return ExecutionStatus.STOPPED, max_sequence
        last = tied[0]
        if last["event"] in (AuditEventType.START.value, AuditEventType.RESUME.value):
            status = ExecutionStatus.RUNNING
        else:
            # STOP and STOP_REQUESTED_AFTER_ALREADY_STOPPED both mean the
            # execution is (still) STOPPED — the latter only ever gets
            # logged because the execution was ALREADY stopped at that
            # point.
            status = ExecutionStatus.STOPPED
        return status, last["sequence"]

    @property
    def status(self) -> ExecutionStatus:
        return self._status

    @property
    def is_stopped(self) -> bool:
        return self._status == ExecutionStatus.STOPPED

    def refresh(self) -> None:
        """Re-reads the audit log and adopts a NEWER status if the log now
        shows one — closes a real, previously-documented gap: a separate
        `KillSwitch` instance (e.g. a `secweave kill` CLI invocation
        pointed at the same execution_id/storage_dir) calling stop() only
        ever wrote to the shared audit log; a DIFFERENT, already-running
        instance (e.g. inside EvidenceHarness.capture()'s loop) had no way
        to notice that write short of being reconstructed from scratch.
        `__init__` already does this recovery once, at construction time —
        this is the same recovery logic, callable again on an existing,
        live instance.

        Only ever moves forward: adopts the disk-recovered state ONLY if
        its `sequence` is strictly greater than what this instance already
        has. This matters even for a single-instance/single-process caller
        — without it, a `refresh()` call racing a concurrent `stop()` on
        THIS SAME instance could read a stale/incomplete view mid-write and
        regress `_status` backward. Comparing by `sequence` (assigned
        atomically under `self._lock` at transition time — see this
        module's docstring) rather than trusting whatever the read
        happened to see keeps this safe regardless of timing.
        """
        recovered_status, recovered_sequence = self._recover_from_audit_log()
        with self._lock:
            if recovered_sequence > self._sequence:
                self._status = recovered_status
                self._sequence = recovered_sequence

    def start(self) -> None:
        with self._lock:
            if self._status != ExecutionStatus.PREPARED:
                raise ValueError(
                    f"start() chỉ hợp lệ từ trạng thái PREPARED — trạng thái hiện tại là "
                    f"'{self._status.value}'."
                )
            self._status = ExecutionStatus.RUNNING
            self._sequence += 1
            event = StopEvent(
                event=AuditEventType.START,
                execution_id=self._execution_id,
                sequence=self._sequence,
                at=datetime.now(timezone.utc),
            )
        # Logged outside the lock — see stop()'s docstring for why cleanup/
        # log I/O should never happen while other callers might be blocked
        # on it. `sequence` (assigned above, INSIDE the lock) is what keeps
        # recovery correct regardless of when this write actually lands.
        self._append_audit_log(event)

    def stop(
        self,
        source: StopSource,
        reason: str,
        actor: Optional[str] = None,
        automatic_threshold_reason: Optional[AutomaticThresholdReason] = None,
    ) -> StopEvent:
        """Any of the 6 values in StopSource can call this, from ANY status
        other than STOPPED — including PREPARED (aborting before start() was
        ever called is a legitimate stop, not an error: a real emergency-stop
        button doesn't first check whether the machine happens to be running
        before it's allowed to work). No negotiation, no permission check
        (see module docstring).

        `automatic_threshold_reason` is REQUIRED when `source=
        StopSource.AUTOMATIC_THRESHOLD` (which of SPEC §6.3's 5 automatic
        conditions fired) and must be omitted for every human source, whose
        reason is free text instead — checked explicitly HERE, at the very
        top, before touching `_status` or running cleanup. Real gap found
        via independent review: StopEvent's own model validator enforces
        the same rule, but only at CONSTRUCTION time — which used to happen
        AFTER this method had already flipped `_status` to STOPPED and run
        `self._cleanup()`. A caller that got the two arguments wrong (e.g.
        forgot `automatic_threshold_reason`) would trigger real, irreversible
        cleanup, yet the raised ValueError meant `_append_audit_log` was
        never reached — so the audit log has NO record the stop (or cleanup)
        ever happened, and a freshly-reconstructed KillSwitch for the same
        execution_id would recover whatever status preceded this call,
        silently resurrecting a run whose cleanup had already, irreversibly,
        run. Validating here, before any state mutation at all, means a
        misused call raises cleanly with NOTHING having happened yet.

        Thread-safe: if two sources call stop() at nearly the same time, the
        first to acquire the lock while status is not yet STOPPED wins — it
        flips to STOPPED and is the only one to run cleanup. A caller that
        loses the race still gets a StopEvent back and logged (event=
        STOP_REQUESTED_AFTER_ALREADY_STOPPED) so the audit trail shows every
        source that tried, not just the winner — losing the race must never
        mean losing the record that a stop was requested.

        The lock is held ONLY for the atomic check-and-flip of `_status` (and
        assigning this event's `sequence` number — see module docstring), not
        for running cleanup or writing the audit log. Real gap found via
        independent review: holding the lock across `self._cleanup()` meant
        a slow or hanging cleanup from the WINNING caller would block every
        OTHER source's stop() call from returning or being logged at all,
        for as long as that cleanup took — exactly the failure mode a kill
        switch must never have (a second source trying to stop things should
        never be made to wait on the first source's cleanup).
        """
        if source == StopSource.AUTOMATIC_THRESHOLD and automatic_threshold_reason is None:
            raise ValueError(
                "source=automatic_threshold yêu cầu automatic_threshold_reason (1 trong 5 điều "
                "kiện SPEC §6.3) — không được để trống khi nguồn dừng là tự động."
            )
        if source != StopSource.AUTOMATIC_THRESHOLD and automatic_threshold_reason is not None:
            raise ValueError("automatic_threshold_reason chỉ có ý nghĩa khi source=automatic_threshold.")

        with self._lock:
            already_stopped = self._status == ExecutionStatus.STOPPED
            self._status = ExecutionStatus.STOPPED
            self._sequence += 1
            sequence = self._sequence
            at = datetime.now(timezone.utc)

        if already_stopped:
            event = StopEvent(
                event=AuditEventType.STOP_REQUESTED_AFTER_ALREADY_STOPPED,
                execution_id=self._execution_id,
                sequence=sequence,
                at=at,
                source=source,
                reason=reason,
                actor=actor,
                cleanup_status=CleanupStatus.SKIPPED,
                automatic_threshold_reason=automatic_threshold_reason,
            )
            self._append_audit_log(event)
            return event

        cleanup_status = CleanupStatus.SKIPPED
        cleanup_error: Optional[str] = None
        if self._cleanup is not None:
            try:
                self._cleanup()
                cleanup_status = CleanupStatus.OK
            except Exception as exc:  # noqa: BLE001 - must not lose the STOPPED transition
                cleanup_status = CleanupStatus.FAILED
                cleanup_error = f"{type(exc).__name__}: {exc}"

        event = StopEvent(
            event=AuditEventType.STOP,
            execution_id=self._execution_id,
            sequence=sequence,
            at=at,
            source=source,
            reason=reason,
            actor=actor,
            cleanup_status=cleanup_status,
            cleanup_error=cleanup_error,
            automatic_threshold_reason=automatic_threshold_reason,
        )
        self._append_audit_log(event)
        return event

    def resume(
        self, actor: Optional[str] = None, authorization_reference: Optional[str] = None
    ) -> None:
        """The ONLY way back to RUNNING — never automatic, no timer, no
        retry-after-cooldown (see module docstring's circuit-breaker note).
        `authorization_reference` is a free-text description of whatever
        real-world approval justified resuming (e.g. "owner re-signed via
        email at ..."); like every other Gate 2/3 reference in this codebase
        during Chặng 1, this is recorded as claimed by the caller, not
        independently verified.
        """
        with self._lock:
            if self._status != ExecutionStatus.STOPPED:
                raise ValueError(
                    f"resume() chỉ hợp lệ từ trạng thái STOPPED — trạng thái hiện tại là "
                    f"'{self._status.value}'."
                )
            self._status = ExecutionStatus.RUNNING
            self._sequence += 1
            event = StopEvent(
                event=AuditEventType.RESUME,
                execution_id=self._execution_id,
                sequence=self._sequence,
                at=datetime.now(timezone.utc),
                actor=actor,
                authorization_reference=authorization_reference,
            )
        # Logged outside the lock, same reasoning as start()/stop(): file I/O
        # should never happen while another caller might be blocked on it.
        self._append_audit_log(event)

    def read_audit_log(self) -> List[dict]:
        """Reads back every entry logged so far (by this instance or any
        prior instance pointed at the same execution_id/storage_dir) — the
        Kill-switch drill test checks "ai/khi nào/vì sao" against this.
        Silently skips any line that fails to parse (see
        _read_audit_log_raw) rather than raising — a corrupted trailing line
        from an interrupted crash must not make the log permanently
        unreadable, or a kill switch's own audit trail becomes another
        single point of failure."""
        entries, _had_corrupt_line = self._read_audit_log_raw()
        return entries

    def _read_audit_log_raw(self) -> Tuple[List[dict], bool]:
        if not self._audit_log_path.exists():
            return [], False
        lines = self._audit_log_path.read_text(encoding="utf-8").splitlines()
        entries: List[dict] = []
        had_corrupt_line = False
        for line in lines:
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                # Real gap found via independent review: __init__ used to
                # call json.loads unconditionally through read_audit_log(),
                # so ANY corrupted line (e.g. a write torn by a hard crash —
                # the exact scenario recovery exists for) made it impossible
                # to even CONSTRUCT a KillSwitch for that execution_id again.
                # A safety mechanism that can't be instantiated after a
                # crash is worse than one that recovers conservatively —
                # see _recover_from_audit_log's fail-safe-to-STOPPED logic.
                had_corrupt_line = True
        return entries, had_corrupt_line

    def _append_audit_log(self, event: StopEvent) -> None:
        # One JSON object per line, opened in append mode. Deliberately
        # called OUTSIDE self._lock by start()/stop()/resume() (see stop()'s
        # docstring) — correctness of WHICH event is "last" no longer
        # depends on this write landing in file order (see `sequence` in the
        # module docstring); correctness of each individual LINE not being
        # corrupted rests on the OS guarantee that a single write() to a
        # file opened with O_APPEND is atomic for entries this small (well
        # under the OS's atomic-write buffer size), not on Python-level
        # locking, so concurrent appends from multiple threads (or, in
        # principle, multiple processes sharing this path) still never
        # interleave into a corrupt line under normal operation — a genuine
        # crash mid-write is the one thing that can still tear a line, which
        # is why _read_audit_log_raw() tolerates that instead of assuming it
        # can never happen. This is a different concurrency shape from
        # EvidenceHarness.generate_marker() (that one guards a single
        # first-write-wins race for a file that doesn't exist yet); this one
        # guards many sequential appends to a file that keeps growing, so
        # the temp-file-then-hard-link fix used there isn't the right tool
        # here — plain append is. Not verified on network filesystems (e.g.
        # NFS), where O_APPEND atomicity is not always guaranteed — local
        # disk only, matching every other artifact this codebase writes.
        line = event.model_dump_json(exclude_none=True) + "\n"
        try:
            with open(self._audit_log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError as exc:
            # Real gap found via independent review: this had ZERO exception
            # handling — a bare OSError (disk full, permission lost) used to
            # escape uncaught out of start()/stop()/resume() with no context.
            # Deliberately NOT the same fix shape as CostService's analogous
            # gap (write first, advance in-memory state only after success):
            # by the time THIS is called, self._status has already flipped
            # (start()/stop()/resume() all update _status INSIDE their own
            # lock, before ever calling this) — for a kill switch specifically,
            # that's the correct order regardless of persistence outcome, since
            # this process's own in-memory `is_stopped` must never be blocked
            # on a disk write succeeding. The real consequence of a failed
            # write here is narrower but still real: a DIFFERENT instance
            # (a restart, a separate `secweave kill`/`resume` invocation)
            # reconstructing from this log later would have no record this
            # transition ever happened. Re-raised as a clear RuntimeError so
            # a caller sees that risk explicitly instead of a bare OSError.
            raise RuntimeError(
                f"KillSwitch cho execution '{self._execution_id}': không ghi được audit log cho "
                f"event '{event.event.value}' — {type(exc).__name__}: {exc}. Trạng thái trong bộ "
                f"nhớ của instance NÀY vẫn đã chuyển đúng (hiện tại: '{self._status.value}'), nhưng "
                "một instance KHÁC (restart, `secweave kill`/`resume` riêng) đọc lại log sau này sẽ "
                "không thấy transition này."
            ) from exc
