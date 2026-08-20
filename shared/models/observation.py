"""UNAPPROVED DRAFT — NOT sourced from SECWEAVE_SPEC.md or A.html.

Checked both documents thoroughly (§4.3, §4.4, §11 in SPEC; the equivalent
sections in A.html) — neither one defines a concrete field-by-field schema
for "normalized observation" the way NormalizedSignal has one in SPEC
§4.1.1. Both only describe it at the concept level ("chuẩn hóa để Oracle đọc
được"). Per the weekly plan, that concrete schema was supposed to come from
a dedicated design step (W3) done WITH a real target owner — that step has
not happened yet in this project (still Chặng 1 — Discovery/preparation, no
real target/owner engaged). So this file is this assistant's own design,
not a documented contract or an owner-approved schema — do not treat any
field here as settled.

Update once Evidence Harness got built (evidence_harness/harness.py): the
HTTP_TRANSACTION path of this schema has now been exercised against a real
target (OWASP Juice Shop, local Docker) — a real 200 response classified as
GRANTED and a real 401 (both a read endpoint and a login attempt) classified
as DENIED, matching curl'd ground truth. That's real validation for
access_result/status_code/channel/hash/metadata on this one channel and
these two status buckets. Still NOT validated: the blind-marker fields
(response_contains_marker/request_contains_marker — no seeding mechanism
exists yet to actually test this end-to-end), AMBIGUOUS's boundary cases
(3xx/5xx/timeouts — only exercised with a mocked transport, not a real
target), and every non-HTTP channel. This remains a draft, just a less
purely-theoretical one on the HTTP path.

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
"""

BLIND_MARKER_PLACEHOLDER = "{{SECWEAVE_BLIND_MARKER}}"
"""SPEC §4.3.4's blind marker — closed 2026-08-19. A FIXED, non-secret
placeholder token: Exploit Agent's prompt teaches the LLM to embed this
EXACT string as one bait-data parameter value of a role=SETUP action, when
it decides a hypothesis benefits from blind-marker verification. The LLM
never sees or invents the REAL marker (a random token from
EvidenceHarness.generate_marker()) — SPEC's own table names ONLY Harness
and Oracle as legitimate readers, explicitly excluding "Exploit Agent /
mọi LLM". cli.py's `execute` substitutes this placeholder for the real
value AFTER the LLM is done and BEFORE Policy Service/Cost Service/
execution ever see it, so the real value never passes through any LLM
context — only this constant (a public token, not a secret) does."""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, model_validator


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

    # Not one of the 3 predicate groups above — used for bait-data seeding
    # actions (SPEC §4.3.4's blind marker: "cơ chế inject vào dữ liệu mồi qua
    # đường setup riêng"). Kept as an observation (not skipped entirely) so
    # the action record stays reproducible (Verification Package field #9:
    # "Action record: đủ để lặp lại"), but evaluate_predicates()
    # (verdict_oracle/predicates.py) ignores this role entirely — it only
    # iterates the 3 groups above, so a SETUP observation can never be
    # mistaken for predicate evidence.
    SETUP = "setup"


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
    action_ref: str  # ActionSpec.action_id of the action that produced this
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


REQUIRED_PREDICATE_GROUPS = frozenset(
    {ObservationRole.MAIN, ObservationRole.POSITIVE_CONTROL, ObservationRole.DENIED_CONTROL}
)


def predicate_results_cover_all_required_groups(results: "List[PredicateResult]") -> bool:
    """VerdictResult/VerificationPackage's own "CONFIRMED requires all
    groups satisfied" validators check `all(r.status == SATISFIED for r in
    results)`, which is vacuously true for a list that's missing a group
    entirely (e.g. only MAIN, no positive_control/denied_control at all) —
    there's nothing in a shorter list to be anything OTHER than satisfied.
    verdict_oracle/oracle.py::assemble_verdict() already enforces "exactly
    these 3 groups, no duplicates" for every verdict it produces — this is
    the same check as an independent model-level backstop for any OTHER
    code path that builds/reloads these models directly (a refactor, a
    JSON reload, a hand-built fixture) without going through
    assemble_verdict().
    """
    groups = [r.group for r in results]
    return set(groups) == REQUIRED_PREDICATE_GROUPS and len(groups) == len(REQUIRED_PREDICATE_GROUPS)


class Verdict(str, Enum):
    """SPEC §4.4.2 — exactly 3 possible verdicts. "Không có verdict thứ tư
    ... Nếu một tình huống không xếp được vào ba giá trị trên, đó là dấu
    hiệu kịch bản chưa định nghĩa đủ chặt — sửa kịch bản, không thêm
    verdict." No "maybe"/"likely" value exists here on purpose."""

    CONFIRMED = "confirmed"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"


class VerdictResult(BaseModel):
    """Output of verdict_oracle/oracle.py::assemble_verdict() — the final
    combination of all 3 predicate-group results into one verdict.
    predicate_results is kept alongside so a human reviewer or the
    Verification Package never has to re-derive why this verdict was
    reached from a separate lookup (same traceability principle as
    NormalizedObservation.raw_evidence_ref)."""

    verdict: Verdict
    reason: str
    predicate_results: List[PredicateResult]

    @model_validator(mode="after")
    def _check_confirmed_requires_all_groups_satisfied(self) -> "VerdictResult":
        # Like PlanCheckResult/CostDecision/ActionPlanResult/
        # HypothesisResult/RuntimeCostDecision/StopEvent, this model
        # enforces its own safety-critical field against the data it's
        # derived from — nothing else stops constructing
        # VerdictResult(verdict=CONFIRMED, predicate_results=[...an
        # UNSATISFIED positive_control...]), the exact failure mode SPEC
        # treats as never acceptable ("thiếu positive control thì không có
        # CONFIRMED", no exceptions).
        #
        # Deliberately ONE-DIRECTIONAL, not a full "iff": verdict_oracle/
        # oracle.py::assemble_verdict() can legitimately return INCONCLUSIVE
        # even when all 3 groups happen to be SATISFIED (the
        # execution_status gate, e.g. a kill-switch STOPPED run, overrides
        # regardless of predicate content) — execution_status isn't a field
        # on this model, so that direction can't be checked here. But
        # verdict==CONFIRMED, in every branch of assemble_verdict(), is only
        # ever reached after main/positive_control/denied_control are ALL
        # SATISFIED — that direction holds unconditionally and is the one
        # that actually matters: a false CONFIRMED, not an overly-cautious
        # INCONCLUSIVE, is the failure SPEC cannot tolerate.
        if self.verdict == Verdict.CONFIRMED and not all(
            r.status == PredicateStatus.SATISFIED for r in self.predicate_results
        ):
            raise ValueError(
                "verdict=confirmed yêu cầu CẢ 3 nhóm predicate đều satisfied — không được set "
                "verdict=confirmed khi bất kỳ nhóm nào unsatisfied/insufficient_data."
            )
        return self

    @model_validator(mode="after")
    def _check_predicate_results_cover_all_required_groups(self) -> "VerdictResult":
        # See predicate_results_cover_all_required_groups()'s docstring for
        # why this check exists. Unconditional here (unlike
        # VerificationPackage's equivalent, scoped to verdict==CONFIRMED
        # only) because this model's own docstring ties it specifically to
        # assemble_verdict()'s output, which always produces exactly these
        # 3 groups for every verdict — there is no legitimate VerdictResult
        # with an incomplete group set.
        if not predicate_results_cover_all_required_groups(self.predicate_results):
            raise ValueError(
                f"predicate_results phải có đúng 1 kết quả cho mỗi nhóm bắt buộc "
                f"{sorted(g.value for g in REQUIRED_PREDICATE_GROUPS)} — nhận được: "
                f"{sorted(r.group.value for r in self.predicate_results)}."
            )
        return self
