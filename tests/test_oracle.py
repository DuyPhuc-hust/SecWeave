import hashlib
import itertools
from datetime import datetime, timezone

import pytest

from shared.models.kill_switch import ExecutionStatus
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
COMPLETED = ExecutionStatus.COMPLETED


def test_all_three_satisfied_is_confirmed():
    result = assemble_verdict(_all(S, S, S), execution_status=COMPLETED)
    assert result.verdict == Verdict.CONFIRMED


def test_main_unsatisfied_with_controls_ok_is_not_reproduced():
    result = assemble_verdict(_all(U, S, S), execution_status=COMPLETED)
    assert result.verdict == Verdict.NOT_REPRODUCED


def test_positive_control_unsatisfied_is_inconclusive_not_not_reproduced():
    # SPEC §4.4.1's explicit override for this one group: can't tell "system
    # correctly blocked" from "bait data missing / capture channel broken" —
    # never treated as a plain "predicate failed" case.
    for main_status in (S, U):
        result = assemble_verdict(_all(main_status, U, S), execution_status=COMPLETED)
        assert result.verdict == Verdict.INCONCLUSIVE


def test_denied_control_unsatisfied_is_not_reproduced():
    # This project's own judgment call (documented in oracle.py) — no
    # explicit SPEC override for this group, falls to the general rule.
    for main_status in (S, U):
        result = assemble_verdict(_all(main_status, S, U), execution_status=COMPLETED)
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
        result = assemble_verdict(_all(main_status, positive_status, denied_status), execution_status=COMPLETED)
        assert result.verdict == Verdict.INCONCLUSIVE, (main_status, positive_status, denied_status)


def test_insufficient_data_takes_priority_over_positive_control_override():
    # main=INSUFFICIENT_DATA + positive=UNSATISFIED: both rules would say
    # INCONCLUSIVE here, but confirms the insufficient-data check runs first
    # and still produces exactly one verdict, not a crash from ambiguity.
    result = assemble_verdict(_all(I, U, S), execution_status=COMPLETED)
    assert result.verdict == Verdict.INCONCLUSIVE


def test_verdict_result_carries_the_original_predicate_results():
    results = _all(S, S, S)
    verdict_result = assemble_verdict(results, execution_status=COMPLETED)
    assert verdict_result.predicate_results == results


def test_verdict_result_rejects_confirmed_when_a_group_is_not_satisfied():
    # Real gap found via independent review: unlike PlanCheckResult/
    # CostDecision/ActionPlanResult/HypothesisResult/RuntimeCostDecision/
    # StopEvent (all of which independently enforce their own safety-
    # critical field against the data it's derived from), VerdictResult had
    # NO such check — nothing stopped constructing a VerdictResult claiming
    # verdict=CONFIRMED alongside predicate_results that don't actually
    # support it, directly violating SPEC's "thiếu positive control thì
    # không có CONFIRMED, không ngoại lệ".
    from pydantic import ValidationError

    from shared.models.observation import VerdictResult

    with pytest.raises(ValidationError):
        VerdictResult(verdict=Verdict.CONFIRMED, reason="x", predicate_results=_all(S, U, S))


def test_verdict_result_allows_inconclusive_even_when_all_groups_satisfied():
    # The validator must be ONE-DIRECTIONAL: assemble_verdict() can
    # legitimately return INCONCLUSIVE while every group is SATISFIED (the
    # execution_status gate overrides regardless of predicate content — see
    # test_non_completed_execution_status_forces_inconclusive_even_when_all_satisfied
    # below) — execution_status isn't a field on VerdictResult, so this
    # direction can't and shouldn't be checked here.
    from shared.models.observation import VerdictResult

    verdict_result = VerdictResult(verdict=Verdict.INCONCLUSIVE, reason="stopped mid-run", predicate_results=_all(S, S, S))
    assert verdict_result.verdict == Verdict.INCONCLUSIVE


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
        assemble_verdict(results, execution_status=COMPLETED)


def test_missing_group_raises_instead_of_defaulting():
    results = [
        _result(ObservationRole.MAIN, S),
        _result(ObservationRole.POSITIVE_CONTROL, S),
    ]
    with pytest.raises(ValueError):
        assemble_verdict(results, execution_status=COMPLETED)


def test_reason_names_which_group_drove_an_inconclusive_verdict():
    results = _all(S, S, I)
    verdict_result = assemble_verdict(results, execution_status=COMPLETED)
    assert "denied_control" in verdict_result.reason


# ----- execution_status gate (SPEC §3.4) -----
# Real gap found via a whole-project independent review: assemble_verdict()
# used to not take execution_status at all, so a run the kill-switch had
# stopped could still produce CONFIRMED on whatever was captured before the
# stop. Only COMPLETED may produce a final CONFIRMED/NOT_REPRODUCED verdict.


@pytest.mark.parametrize(
    "status",
    [
        ExecutionStatus.PREPARED,
        ExecutionStatus.RUNNING,
        ExecutionStatus.STOPPED,
        ExecutionStatus.ERROR,
        ExecutionStatus.BLOCKED,
    ],
)
def test_non_completed_execution_status_forces_inconclusive_even_when_all_satisfied(status):
    # Even the "everything satisfied, would otherwise be CONFIRMED" case
    # must NOT slip through if the execution itself never reached COMPLETED.
    result = assemble_verdict(_all(S, S, S), execution_status=status)
    assert result.verdict == Verdict.INCONCLUSIVE
    assert status.value in result.reason


def test_completed_execution_status_allows_the_normal_verdict_logic_to_run():
    result = assemble_verdict(_all(S, S, S), execution_status=ExecutionStatus.COMPLETED)
    assert result.verdict == Verdict.CONFIRMED


_artifact_counter = itertools.count()


def _observation(tmp_path=None, **overrides) -> NormalizedObservation:
    """When tmp_path is given, writes a REAL file and computes its REAL hash
    (needed for decide(), which goes through evaluate_predicates()'s hash
    check); when omitted, raw_evidence_hash/ref are inert placeholders,
    fine for tests that never touch decide()/evaluate_predicates()."""
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
    if tmp_path is not None:
        content = f"evidence-{next(_artifact_counter)}".encode()
        artifact_path = tmp_path / f"artifact_{next(_artifact_counter)}.json"
        artifact_path.write_bytes(content)
        defaults["raw_evidence_hash"] = "sha256:" + hashlib.sha256(content).hexdigest()
        defaults["raw_evidence_ref"] = str(artifact_path)
    return NormalizedObservation(**defaults)


def test_decide_runs_evaluate_predicates_and_assemble_verdict_together(tmp_path):
    observations = [
        _observation(
            tmp_path,
            role=ObservationRole.MAIN,
            access_result=AccessResult.GRANTED,
            response_contains_marker=True,
            request_contains_marker=False,
        ),
        _observation(tmp_path, role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.GRANTED),
        _observation(tmp_path, role=ObservationRole.DENIED_CONTROL, access_result=AccessResult.DENIED),
    ]
    result = decide(observations, execution_status=COMPLETED)
    assert result.verdict == Verdict.CONFIRMED
    assert len(result.predicate_results) == 3


def test_decide_with_no_observations_at_all_is_inconclusive():
    result = decide([], execution_status=COMPLETED)
    assert result.verdict == Verdict.INCONCLUSIVE


def test_decide_is_inconclusive_when_execution_status_is_stopped_even_if_fully_satisfied(tmp_path):
    observations = [
        _observation(
            tmp_path,
            role=ObservationRole.MAIN,
            access_result=AccessResult.GRANTED,
            response_contains_marker=True,
            request_contains_marker=False,
        ),
        _observation(tmp_path, role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.GRANTED),
        _observation(tmp_path, role=ObservationRole.DENIED_CONTROL, access_result=AccessResult.DENIED),
    ]
    result = decide(observations, execution_status=ExecutionStatus.STOPPED)
    assert result.verdict == Verdict.INCONCLUSIVE
