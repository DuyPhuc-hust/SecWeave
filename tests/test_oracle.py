from datetime import datetime, timezone

import pytest

from shared.models.observation import (
    AccessResult,
    EvidenceChannel,
    NormalizedObservation,
    ObservationRole,
    PredicateResult,
    PredicateStatus,
    Verdict,
)
from verdict_oracle.oracle import assemble_verdict, decide


def _result(group: ObservationRole, status: PredicateStatus, reason: str = "x") -> PredicateResult:
    return PredicateResult(group=group, status=status, reason=reason)


def _all(main: PredicateStatus, positive: PredicateStatus, denied: PredicateStatus):
    return [
        _result(ObservationRole.MAIN, main),
        _result(ObservationRole.POSITIVE_CONTROL, positive),
        _result(ObservationRole.DENIED_CONTROL, denied),
    ]


S = PredicateStatus.SATISFIED
U = PredicateStatus.UNSATISFIED
I = PredicateStatus.INSUFFICIENT_DATA


def test_all_three_satisfied_is_confirmed():
    result = assemble_verdict(_all(S, S, S))
    assert result.verdict == Verdict.CONFIRMED


def test_main_unsatisfied_with_controls_ok_is_not_reproduced():
    result = assemble_verdict(_all(U, S, S))
    assert result.verdict == Verdict.NOT_REPRODUCED


def test_positive_control_unsatisfied_is_inconclusive_not_not_reproduced():
    # SPEC §4.4.1's explicit override for this one group: can't tell "system
    # correctly blocked" from "bait data missing / capture channel broken" —
    # never treated as a plain "predicate failed" case.
    for main_status in (S, U):
        result = assemble_verdict(_all(main_status, U, S))
        assert result.verdict == Verdict.INCONCLUSIVE


def test_denied_control_unsatisfied_is_not_reproduced():
    # This project's own judgment call (documented in oracle.py) — no
    # explicit SPEC override for this group, falls to the general rule.
    for main_status in (S, U):
        result = assemble_verdict(_all(main_status, S, U))
        assert result.verdict == Verdict.NOT_REPRODUCED


def test_any_insufficient_data_is_inconclusive_regardless_of_others():
    combos = [
        (I, S, S),
        (S, I, S),
        (S, S, I),
        (I, I, I),
        (I, U, S),
        (U, I, U),
    ]
    for main_status, positive_status, denied_status in combos:
        result = assemble_verdict(_all(main_status, positive_status, denied_status))
        assert result.verdict == Verdict.INCONCLUSIVE, (main_status, positive_status, denied_status)


def test_insufficient_data_takes_priority_over_positive_control_override():
    # main=INSUFFICIENT_DATA + positive=UNSATISFIED: both rules would say
    # INCONCLUSIVE here, but confirms the insufficient-data check runs first
    # and still produces exactly one verdict, not a crash from ambiguity.
    result = assemble_verdict(_all(I, U, S))
    assert result.verdict == Verdict.INCONCLUSIVE


def test_verdict_result_carries_the_original_predicate_results():
    results = _all(S, S, S)
    verdict_result = assemble_verdict(results)
    assert verdict_result.predicate_results == results


def test_duplicate_group_raises_instead_of_silently_picking_one():
    # Real gap found via review: a by_group dict-comprehension built from a
    # malformed list would silently keep only the LAST duplicate — this
    # codebase's own documented failure pattern elsewhere (predicates.py).
    # assemble_verdict() is a safety-critical decision point, so this must
    # raise loudly instead of guessing.
    results = [
        _result(ObservationRole.MAIN, S),
        _result(ObservationRole.MAIN, U),
        _result(ObservationRole.POSITIVE_CONTROL, S),
        _result(ObservationRole.DENIED_CONTROL, S),
    ]
    with pytest.raises(ValueError):
        assemble_verdict(results)


def test_missing_group_raises_instead_of_defaulting():
    results = [
        _result(ObservationRole.MAIN, S),
        _result(ObservationRole.POSITIVE_CONTROL, S),
    ]
    with pytest.raises(ValueError):
        assemble_verdict(results)


def test_reason_names_which_group_drove_an_inconclusive_verdict():
    results = _all(S, S, I)
    verdict_result = assemble_verdict(results)
    assert "denied_control" in verdict_result.reason


def _observation(**overrides) -> NormalizedObservation:
    defaults = dict(
        observation_id="obs_1",
        action_ref="act_1",
        role=ObservationRole.MAIN,
        captured_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        identity="some-identity",
        execution_id="exec_1",
        target_id="tgt_1",
        target_revision_id="rev_1",
        channel=EvidenceChannel.HTTP_TRANSACTION,
        raw_evidence_size_bytes=512,
        raw_evidence_hash="sha256:0",
        raw_evidence_ref="artifact_1",
        access_result=AccessResult.AMBIGUOUS,
    )
    defaults.update(overrides)
    return NormalizedObservation(**defaults)


def test_decide_runs_evaluate_predicates_and_assemble_verdict_together():
    observations = [
        _observation(
            role=ObservationRole.MAIN,
            access_result=AccessResult.GRANTED,
            response_contains_marker=True,
            request_contains_marker=False,
        ),
        _observation(role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.GRANTED),
        _observation(role=ObservationRole.DENIED_CONTROL, access_result=AccessResult.DENIED),
    ]
    result = decide(observations)
    assert result.verdict == Verdict.CONFIRMED
    assert len(result.predicate_results) == 3


def test_decide_with_no_observations_at_all_is_inconclusive():
    result = decide([])
    assert result.verdict == Verdict.INCONCLUSIVE
