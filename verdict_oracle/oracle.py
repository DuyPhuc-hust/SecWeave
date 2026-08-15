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
"""

from typing import List

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


def assemble_verdict(results: List[PredicateResult]) -> VerdictResult:
    """`results` should be exactly the 3-element list evaluate_predicates()
    produces (one per required group). Explicitly validated here (unlike a
    private internal helper) because this function is this tier's actual
    safety-critical decision point and is called directly by tests/other
    callers, not only through evaluate_predicates() — a `by_group` dict
    built from a malformed list (a duplicate group, or one missing) must
    never silently pick an arbitrary interpretation for a verdict this
    consequential (this codebase has a documented history of exactly this
    dict-comprehension-silently-keeps-last-duplicate bug elsewhere).
    """
    groups_present = [r.group for r in results]
    if set(groups_present) != _REQUIRED_GROUPS or len(groups_present) != len(_REQUIRED_GROUPS):
        raise ValueError(
            f"assemble_verdict() cần đúng 1 PredicateResult cho mỗi nhóm {sorted(g.value for g in _REQUIRED_GROUPS)}, "
            f"nhận được: {sorted(g.value for g in groups_present)}"
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


def decide(observations: List[NormalizedObservation]) -> VerdictResult:
    """Convenience entry point: evaluate_predicates() + assemble_verdict()
    in one call, for callers that only care about the final verdict."""
    return assemble_verdict(evaluate_predicates(observations))
