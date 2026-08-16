"""Verdict Oracle's final decision step — SPEC §4.4.2. Combines the 3
predicate-group results from predicates.py into exactly one of the 3
required verdicts. Pure rule code, no LLM (SPEC §4.4: "Rule code thuần,
không gọi LLM").

Until now this final combination step didn't exist anywhere in the codebase
— evaluate_predicates() only produced the 3 per-group results, never the
actual CONFIRMED/NOT_REPRODUCED/INCONCLUSIVE verdict the tier is named
after. This module is that missing step.

Mapping used below — grounded in SPEC §4.4.1/§4.4.2, with one interpretive
call flagged explicitly:
- Any group INSUFFICIENT_DATA -> INCONCLUSIVE. Directly matches §4.4.2's own
  INCONCLUSIVE condition ("thiếu bằng chứng ... predicate không chạy đủ").
- positive_control UNSATISFIED -> INCONCLUSIVE. Not the general "predicate
  bắt buộc không thỏa mãn -> NOT_REPRODUCED" rule — §4.4.1's own row for
  this group explicitly overrides it: "Nếu không thỏa -> INCONCLUSIVE (không
  phân biệt được 'hệ thống chặn đúng' với 'dữ liệu mồi không tồn tại'/'kênh
  thu hỏng')". This is the one case SPEC names explicitly, so it's applied
  literally, not inferred.
- denied_control UNSATISFIED -> NOT_REPRODUCED. SPEC has NO equivalent
  explicit override for this group (unlike positive_control's), so this
  falls to §4.4.2's general rule for a required predicate failing with
  otherwise-sufficient evidence. This is this module's own judgment call,
  not a literal SPEC quote — flagged here so a future reviewer knows to
  scrutinize it: the alternative reading (denied_control failing also means
  INCONCLUSIVE, on the theory that it equally can't distinguish "real bug"
  from "broken test setup") is defensible too. Chose NOT_REPRODUCED because
  §4.4.1's purpose statement for this group ("Chống trường hợp hệ thống trả
  dữ liệu cho tất cả vì lý do khác") describes a specific alternative
  explanation being found, not an inconclusive test — closer in kind to "the
  suspected behavior didn't reproduce as hypothesized" than to "test broke".
- main UNSATISFIED (with positive_control and denied_control both
  SATISFIED) -> NOT_REPRODUCED. The direct, unambiguous case.
- All 3 SATISFIED -> CONFIRMED. SPEC: "thiếu positive control thì không có
  CONFIRMED" (no exceptions) — satisfied here by construction, since
  reaching this branch already required positive_control SATISFIED.

Two gaps found via a whole-project independent review (2026-08-15/16), fixed
here and in predicates.py — neither had been caught by any prior review
because no prior review had looked at this module from the specific angle
of "what SPEC controls does this violate," only "is the predicate logic
correct" (which it always was):

- SPEC §3.4's execution_status matrix: only `COMPLETED` can produce a final
  CONFIRMED/NOT_REPRODUCED verdict; `PREPARED`/`RUNNING` means no verdict
  yet, and `BLOCKED`/`STOPPED`/`ERROR` means no FINAL verification verdict —
  "nếu một biểu mẫu buộc phải ghi gì đó thì chỉ được ghi INCONCLUSIVE."
  `assemble_verdict()` didn't take execution_status as input at all before
  this fix, so a run stopped by the kill-switch (shared/kill_switch.py)
  could still produce CONFIRMED on whatever observations happened to be
  captured before the stop. Now REQUIRED (no default) so no caller can
  silently skip thinking about it — see the check right after group
  validation below.
- SPEC §6.4 control #8: "Hash không khớp thì không được CONFIRMED" — no
  exceptions in MVP. Implemented in predicates.py's evaluate_predicates(),
  not here: a hash mismatch (or unreadable raw evidence file) on any of the
  3 groups' observations now surfaces as PredicateStatus.INSUFFICIENT_DATA
  BEFORE that observation's role-specific check ever runs, which flows
  through this function's EXISTING "any INSUFFICIENT_DATA -> INCONCLUSIVE"
  rule with no new code path needed here. Chosen over a bespoke 4th status
  or a separate check bolted onto this function specifically because (a)
  PredicateStatus is a closed 3-value enum by design (SPEC §11: "không có
  trạng thái thứ tư"), and (b) `assemble_verdict()` only ever sees
  PredicateResult objects, never the underlying NormalizedObservation with
  its raw_evidence_ref — only evaluate_predicates() has both the observation
  and the file path to actually re-read and compare.
"""

from typing import List

from shared.models.kill_switch import ExecutionStatus
from shared.models.observation import (
    NormalizedObservation,
    ObservationRole,
    PredicateResult,
    PredicateStatus,
    Verdict,
    VerdictResult,
)
from verdict_oracle.predicates import evaluate_predicates


_REQUIRED_GROUPS = frozenset(
    {ObservationRole.MAIN, ObservationRole.POSITIVE_CONTROL, ObservationRole.DENIED_CONTROL}
)


def assemble_verdict(results: List[PredicateResult], execution_status: ExecutionStatus) -> VerdictResult:
    """`results` should be exactly the 3-element list evaluate_predicates()
    produces (one per required group). Explicitly validated here (unlike a
    private internal helper) because this function is this tier's actual
    safety-critical decision point and is called directly by tests/other
    callers, not only through evaluate_predicates() — a `by_group` dict
    built from a malformed list (a duplicate group, or one missing) must
    never silently pick an arbitrary interpretation for a verdict this
    consequential (this codebase has a documented history of exactly this
    dict-comprehension-silently-keeps-last-duplicate bug elsewhere).

    `execution_status` is REQUIRED, not optional/defaulted — see this
    module's docstring for why a silent default would risk quietly
    reintroducing the exact bug this parameter was added to close. Only
    `ExecutionStatus.COMPLETED` can produce CONFIRMED/NOT_REPRODUCED; every
    other status forces INCONCLUSIVE regardless of what the predicates say
    (SPEC §3.4).
    """
    groups_present = [r.group for r in results]
    if set(groups_present) != _REQUIRED_GROUPS or len(groups_present) != len(_REQUIRED_GROUPS):
        raise ValueError(
            f"assemble_verdict() cần đúng 1 PredicateResult cho mỗi nhóm {sorted(g.value for g in _REQUIRED_GROUPS)}, "
            f"nhận được: {sorted(g.value for g in groups_present)}"
        )

    if execution_status != ExecutionStatus.COMPLETED:
        return VerdictResult(
            verdict=Verdict.INCONCLUSIVE,
            reason=(
                f"execution_status='{execution_status.value}', không phải COMPLETED — SPEC §3.4: chỉ "
                "COMPLETED mới có thể có final verification verdict; PREPARED/RUNNING nghĩa là chưa có "
                "verdict, còn BLOCKED/STOPPED/ERROR nghĩa là không có final verdict, nếu buộc phải ghi "
                "gì đó thì chỉ được ghi INCONCLUSIVE."
            ),
            predicate_results=results,
        )

    by_group = {r.group: r for r in results}
    main = by_group[ObservationRole.MAIN]
    positive = by_group[ObservationRole.POSITIVE_CONTROL]
    denied = by_group[ObservationRole.DENIED_CONTROL]

    insufficient = [r for r in (main, positive, denied) if r.status == PredicateStatus.INSUFFICIENT_DATA]
    if insufficient:
        detail = "; ".join(f"{r.group.value}: {r.reason}" for r in insufficient)
        return VerdictResult(
            verdict=Verdict.INCONCLUSIVE,
            reason=f"Thiếu bằng chứng ở {len(insufficient)} nhóm predicate — {detail}",
            predicate_results=results,
        )

    if positive.status == PredicateStatus.UNSATISFIED:
        return VerdictResult(
            verdict=Verdict.INCONCLUSIVE,
            reason=(
                "Positive control không thỏa mãn — không phân biệt được 'hệ thống chặn đúng quyền' "
                f"với 'dữ liệu mồi không tồn tại/kênh thu hỏng' (SPEC §4.4.1). {positive.reason}"
            ),
            predicate_results=results,
        )

    if denied.status == PredicateStatus.UNSATISFIED:
        return VerdictResult(
            verdict=Verdict.NOT_REPRODUCED,
            reason=(
                "Denied control không thỏa mãn — hệ thống có thể trả dữ liệu cho mọi người vì lý do "
                f"ngoài dự kiến, không phải đúng ranh giới quyền đang nghi ngờ. {denied.reason}"
            ),
            predicate_results=results,
        )

    if main.status == PredicateStatus.SATISFIED:
        return VerdictResult(
            verdict=Verdict.CONFIRMED,
            reason="Cả 3 nhóm predicate đều thỏa mãn — hành vi nghi ngờ đã tái hiện được, có bằng "
            "chứng máy đọc được kèm theo.",
            predicate_results=results,
        )

    return VerdictResult(
        verdict=Verdict.NOT_REPRODUCED,
        reason=f"Predicate chính không thỏa mãn — hành vi nghi ngờ không tái hiện. {main.reason}",
        predicate_results=results,
    )


def decide(observations: List[NormalizedObservation], execution_status: ExecutionStatus) -> VerdictResult:
    """Convenience entry point: evaluate_predicates() + assemble_verdict()
    in one call, for callers that only care about the final verdict.
    `execution_status` is passed straight through — see assemble_verdict's
    docstring for why it's required, not optional."""
    return assemble_verdict(evaluate_predicates(observations), execution_status)
