"""UNAPPROVED DRAFT — NOT sourced from SECWEAVE_SPEC.md or A.html.

Checked both documents thoroughly (§4.3, §4.4, §11 in SPEC; the equivalent
sections in A.html) — neither one defines a concrete field-by-field schema
for "normalized observation" the way NormalizedSignal has one in SPEC
§4.1.1. Both only describe it at the concept level ("chuẩn hóa để Oracle đọc
được"). Per the weekly plan, that concrete schema was supposed to come from
a dedicated design step (W3) done WITH a real target owner — that step has
not happened yet in this project (still Chặng 1 — Discovery/preparation, no
real target/owner engaged). So this file is this assistant's own design to
unblock drafting predicate logic, not a documented contract. Expect it to be
rewritten once a real target/owner defines what an actual observation looks
like for their system — do not treat any field here as settled.

What IS grounded in the docs (used directly below, not guessed):
- SPEC §4.3.2: "Mỗi artifact lưu kèm: thời điểm, danh tính thực thi,
  execution ID, target, revision, kênh thu, kích thước, hash" — this is a
  concrete, named list of metadata every artifact carries. Since a
  NormalizedObservation is 1:1 with an Artifact (SPEC's ER diagram), it
  should carry all 8 of these, not a subset — a predicate or a human
  reviewer must be able to trace any observation back to exactly which
  artifact, from which execution, against which target/revision, produced
  it, without a second lookup.
- SPEC §4.3.2's 5 collection channels (HTTP transaction, exit code/stdout,
  application log, before/after data-state, UI screenshot/recording).
- SPEC §4.3: Evidence Harness "không diễn giải, không kết luận" — this
  schema avoids fields that would be a security judgment (e.g. no
  "is_vulnerable" field). access_result is a MECHANICAL bucketing of
  status/response shape, not a verdict — verdicts remain Oracle's job via
  predicates, never something this model states directly.
- SPEC §4.3.3: artifact hash integrity — a reviewer/predicate should be able
  to see the hash without a separate lookup, since human review is required
  to check hashes before releasing a package.
- SPEC §4.4.1: the 3 predicate groups and the blind-marker example are the
  only concrete predicate mechanics SPEC actually works through, so this
  schema is scoped to that: HTTP-based, marker-capable observations. Fields
  needed for a non-HTTP or non-marker scenario are not attempted here.

What is NOT grounded (this assistant's own choices, flagged so a future
redesign knows what to scrutinize hardest):
- AccessResult as a 3-state (granted/denied/ambiguous) bucket instead of a
  plain bool — added because collapsing an unexpected response (timeout,
  500, redirect loop) into True/False would force a predicate to guess;
  AMBIGUOUS lets it fall back to insufficient_data honestly instead.
- EvidenceChannel lists all 5 channels from SPEC §4.3.2, but only
  HTTP_TRANSACTION has any real producer today — ActionSpec
  (exploit_agent/agent.py) only models HTTP actions (method + target URL).
  Naming the other 4 here is cheap and keeps the schema from silently
  assuming HTTP is the only channel that will ever exist, but constructing
  an observation for one of them would need real Harness work first.
- A REAL GAP this schema surfaces but does not fix: ActionSpec has no field
  today saying "this action is meant to serve as the positive control" (or
  denied control) — Exploit Agent's prompt doesn't ask the LLM to design a
  3-role action set either. Without that, nothing can actually produce a
  correctly-tagged `role` for these observations yet. This schema assumes
  that gap gets closed later (either in ActionSpec or in how a human/Oracle
  assembles a run's observations); it isn't closed here.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class ObservationRole(str, Enum):
    """Which of the 3 required predicate groups (SPEC §4.4.1) this
    observation was captured for. Assigned when the action plan is designed
    (an action is executed AS the main test, AS the positive control, or AS
    the denied control) — the Oracle must not have to guess this from the
    observation's content.
    """

    MAIN = "main"
    POSITIVE_CONTROL = "positive_control"
    DENIED_CONTROL = "denied_control"


class EvidenceChannel(str, Enum):
    """SPEC §4.3.2's 5 collection channels. Only HTTP_TRANSACTION has an
    actual producer today (see this file's docstring) — the other 4 are
    named for completeness against the spec, not because anything can
    populate them yet.
    """

    HTTP_TRANSACTION = "http_transaction"
    PROCESS_EXECUTION = "process_execution"  # exit code + stdout/stderr
    APPLICATION_LOG = "application_log"
    DATA_STATE_COMPARISON = "data_state_comparison"  # read-only before/after
    UI_CAPTURE = "ui_capture"  # screenshot + screen recording (Playwright)


class AccessResult(str, Enum):
    """Mechanical classification of the actor's outcome for this one
    action — NOT a security verdict (SPEC: Harness "không diễn giải, không
    kết luận"). A predicate still has to decide satisfied/unsatisfied from
    this; this field only spares every predicate from re-implementing "what
    counts as denied" from a raw status code.

    AMBIGUOUS exists so an unexpected response (e.g. a 500, a redirect loop,
    a timeout) doesn't get force-fit into granted/denied — a predicate
    reading AMBIGUOUS should treat that as insufficient_data rather than
    guessing which way it leans.
    """

    GRANTED = "granted"
    DENIED = "denied"
    AMBIGUOUS = "ambiguous"


class NormalizedObservation(BaseModel):
    """One executed action's evidence, normalized for the Oracle to read.
    1:1 with an Artifact (SPEC's ER diagram: Artifact ||--|| NormalizedObservation).

    Evidence Harness would be the one producing this from raw evidence — it
    doesn't exist yet, so this shape is necessarily provisional (see this
    file's module docstring).
    """

    # --- Identity of this observation and what produced it ---
    observation_id: str
    action_ref: str  # points back to the ActionSpec that produced this
    role: ObservationRole

    # --- SPEC §4.3.2's 8 required artifact metadata fields, verbatim ---
    captured_at: datetime  # "thời điểm"
    identity: str  # "danh tính thực thi"
    execution_id: str  # "execution ID"
    target_id: str  # "target" — matches Authorization.target_id's naming
    target_revision_id: str  # "revision" — matches Authorization.target_revision_id
    channel: EvidenceChannel  # "kênh thu"
    raw_evidence_size_bytes: int  # "kích thước"
    raw_evidence_hash: str  # "hash" — SPEC §4.3.3: integrity check must not
    # require a second lookup to see this value

    raw_evidence_ref: str  # pointer to the actual raw artifact (SPEC P2:
    # evidence before assertion — every field below must be traceable back
    # to this artifact; if a field here and the raw artifact ever disagree,
    # SPEC §4.3.1 says raw wins, not this derived record)

    # --- Mechanical, channel-derived signal ---
    # Required on every observation, but only meaningful for
    # channel=HTTP_TRANSACTION (the only channel with a real producer today —
    # see this file's module docstring). If a future non-HTTP channel is
    # added, "granted/denied" may not map cleanly onto it (e.g. what would
    # "denied" mean for a screen recording?) — that channel's producer should
    # use AMBIGUOUS rather than force a fit, or this field should be
    # reconsidered as Optional at that point rather than stretched further.
    access_result: AccessResult
    status_code: Optional[int] = None  # HTTP_TRANSACTION only

    # --- Blind-marker scenario fields (SPEC §4.3.4, §4.4.1) — None when this
    # scenario doesn't use a blind marker, distinct from False ---
    response_contains_marker: Optional[bool] = None
    request_contains_marker: Optional[bool] = None


class PredicateStatus(str, Enum):
    """SPEC §11 glossary: a predicate returns "thỏa mãn/không thỏa
    mãn/không đủ dữ liệu" — exactly 3 states, no partial/maybe state."""

    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    INSUFFICIENT_DATA = "insufficient_data"


class PredicateResult(BaseModel):
    # Typed as ObservationRole (not a bare str) so nothing can assign an
    # arbitrary/mistyped string here — every result must name one of the 3
    # groups SPEC §4.4.1 actually defines.
    group: ObservationRole
    status: PredicateStatus
    reason: str
