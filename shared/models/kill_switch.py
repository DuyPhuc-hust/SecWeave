"""Data model for the kill-switch mechanism — SPEC §6.3 ("năm nguồn người +
một ngưỡng tự động") and §3.4 (execution_status state machine). See
shared/kill_switch.py for the KillSwitch class that uses these types.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, model_validator


class StopSource(str, Enum):
    """SPEC §6.3's table, verbatim — 5 human sources + 1 automatic
    threshold. No source outside this closed set exists."""

    OPERATOR = "operator"
    TARGET_OWNER = "target_owner"
    INFRA_OWNER = "infra_owner"
    DATA_ISMS_OWNER = "data_isms_owner"
    INCIDENT_RESPONDER = "incident_responder"
    AUTOMATIC_THRESHOLD = "automatic_threshold"


class AutomaticThresholdReason(str, Enum):
    """SPEC §6.3's 5 automatic-threshold conditions, verbatim. Only
    meaningful when source=AUTOMATIC_THRESHOLD — a human source's reason for
    stopping is free text (KillSwitch.stop()'s `reason` parameter), since a
    person's reason isn't a fixed enum the way an automatic trigger is."""

    COST_CAP_EXCEEDED = "cost_cap_exceeded"
    ACTION_COUNT_EXCEEDED = "action_count_exceeded"
    OUTSIDE_TIME_WINDOW = "outside_time_window"
    HASH_MISMATCH = "hash_mismatch"
    REAL_PRODUCTION_DATA_DETECTED = "real_production_data_detected"


class ExecutionStatus(str, Enum):
    """SPEC §3.4's state machine, verbatim (6 states). KillSwitch only
    actively drives PREPARED->RUNNING (start()), RUNNING->STOPPED (stop()),
    and STOPPED->RUNNING (resume()) — COMPLETED/ERROR/BLOCKED belong to the
    "Execute" orchestration loop (bước 6, SPEC §5.1), which doesn't exist as
    code yet. Naming all 6 here (not just the 3 KillSwitch drives) keeps this
    enum aligned with the spec's full diagram instead of a partial one a
    future integration would have to redefine from scratch."""

    PREPARED = "prepared"
    RUNNING = "running"
    STOPPED = "stopped"
    COMPLETED = "completed"
    ERROR = "error"
    BLOCKED = "blocked"


class CleanupStatus(str, Enum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"  # no cleanup callable was configured, or N/A for this event type


class AuditEventType(str, Enum):
    # Logged so a NEW KillSwitch instance constructed later for the same
    # execution_id (crash recovery, a separate CLI/API process, a worker
    # restart) can tell RUNNING apart from PREPARED by reading the audit log
    # alone, instead of always starting at PREPARED regardless of history
    # and silently un-stopping a STOPPED execution — see KillSwitch.
    # __init__'s status-recovery logic.
    START = "start"
    STOP = "stop"
    # A source called stop() after the run was already STOPPED — recorded so
    # the audit trail shows every source that tried, not just the winner of
    # the race (see KillSwitch.stop()'s docstring).
    STOP_REQUESTED_AFTER_ALREADY_STOPPED = "stop_requested_after_already_stopped"
    RESUME = "resume"


class StopEvent(BaseModel):
    """One line of the kill-switch audit log. `actor`/`authorization_reference`
    are free-text and caller-supplied, never independently verified — no Gate
    2/3 identity-verification exists in this codebase (same "gates assumed
    approved, operator-supplied" situation as Authorization.identity,
    allowlist entries, and login() credentials elsewhere in Chặng 1). This
    model can only record what the caller claims, not confirm it.
    """

    event: AuditEventType
    execution_id: str
    # Assigned atomically under KillSwitch's lock at the moment of the real
    # status transition, NOT at the moment this line is physically written
    # to disk — status recovery (KillSwitch._recover_status_from_audit_log)
    # cannot use physical file-append order as a proxy for "what happened
    # last," since a slow cleanup() delays STOP's write, so a concurrent
    # (fast) RESUME on another thread could write its line to disk FIRST
    # even though the STOP's real transition happened first. `sequence`
    # decouples "true logical order" from "when the slow I/O happened to
    # land."
    sequence: int
    at: datetime
    source: Optional[StopSource] = None  # None for a "resume" event
    reason: Optional[str] = None  # None for a "resume" event
    actor: Optional[str] = None
    authorization_reference: Optional[str] = None  # only meaningful for "resume"
    cleanup_status: Optional[CleanupStatus] = None  # only meaningful for "stop" events
    cleanup_error: Optional[str] = None
    # Which of SPEC §6.3's 5 automatic conditions triggered this stop — only
    # meaningful when source=AUTOMATIC_THRESHOLD. Kept as a structured enum
    # rather than embedded as free text in `reason` so it can be reliably
    # queried later (e.g. "how many times did each of the 5 automatic
    # conditions fire across the whole project").
    automatic_threshold_reason: Optional[AutomaticThresholdReason] = None

    @model_validator(mode="after")
    def _check_automatic_threshold_reason_consistency(self) -> "StopEvent":
        if self.source == StopSource.AUTOMATIC_THRESHOLD and self.automatic_threshold_reason is None:
            raise ValueError(
                "source=automatic_threshold yêu cầu automatic_threshold_reason (1 trong 5 điều "
                "kiện SPEC §6.3) — không được để trống khi nguồn dừng là tự động."
            )
        if self.source != StopSource.AUTOMATIC_THRESHOLD and self.automatic_threshold_reason is not None:
            raise ValueError(
                "automatic_threshold_reason chỉ có ý nghĩa khi source=automatic_threshold."
            )
        return self
