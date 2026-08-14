from datetime import datetime, timezone

from shared.models.observation import (
    AccessResult,
    EvidenceChannel,
    NormalizedObservation,
    ObservationRole,
    PredicateStatus,
)
from verdict_oracle.predicates import (
    check_denied_control,
    check_main_predicate,
    check_positive_control,
    evaluate_predicates,
)


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


# ----- Group 1 — main predicate -----


def test_main_predicate_satisfied_when_marker_in_response_not_in_request():
    observation = _observation(
        role=ObservationRole.MAIN,
        access_result=AccessResult.GRANTED,
        response_contains_marker=True,
        request_contains_marker=False,
    )
    result = check_main_predicate(observation)
    assert result.status == PredicateStatus.SATISFIED


def test_main_predicate_unsatisfied_when_marker_absent_from_response():
    observation = _observation(
        role=ObservationRole.MAIN,
        access_result=AccessResult.GRANTED,
        response_contains_marker=False,
        request_contains_marker=False,
    )
    result = check_main_predicate(observation)
    assert result.status == PredicateStatus.UNSATISFIED


def test_main_predicate_unsatisfied_when_marker_also_present_in_request():
    # Marker in both request and response isn't proof of a leak — could just
    # be the agent's own input reflected back.
    observation = _observation(
        role=ObservationRole.MAIN,
        access_result=AccessResult.GRANTED,
        response_contains_marker=True,
        request_contains_marker=True,
    )
    result = check_main_predicate(observation)
    assert result.status == PredicateStatus.UNSATISFIED


def test_main_predicate_insufficient_data_when_marker_fields_missing():
    observation = _observation(role=ObservationRole.MAIN, access_result=AccessResult.GRANTED)
    result = check_main_predicate(observation)
    assert result.status == PredicateStatus.INSUFFICIENT_DATA


def test_main_predicate_insufficient_data_when_wrong_role():
    observation = _observation(
        role=ObservationRole.POSITIVE_CONTROL,
        access_result=AccessResult.GRANTED,
        response_contains_marker=True,
        request_contains_marker=False,
    )
    result = check_main_predicate(observation)
    assert result.status == PredicateStatus.INSUFFICIENT_DATA


# ----- Group 2 — positive control -----


def test_positive_control_satisfied_when_owner_can_read():
    observation = _observation(role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.GRANTED)
    result = check_positive_control(observation)
    assert result.status == PredicateStatus.SATISFIED


def test_positive_control_unsatisfied_when_owner_cannot_read():
    observation = _observation(role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.DENIED)
    result = check_positive_control(observation)
    assert result.status == PredicateStatus.UNSATISFIED


def test_positive_control_insufficient_data_when_access_result_ambiguous():
    observation = _observation(role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.AMBIGUOUS)
    result = check_positive_control(observation)
    assert result.status == PredicateStatus.INSUFFICIENT_DATA


def test_positive_control_insufficient_data_when_wrong_role():
    observation = _observation(role=ObservationRole.MAIN, access_result=AccessResult.GRANTED)
    result = check_positive_control(observation)
    assert result.status == PredicateStatus.INSUFFICIENT_DATA


# ----- Group 3 — denied control -----


def test_denied_control_satisfied_when_unauthorized_identity_is_denied():
    observation = _observation(role=ObservationRole.DENIED_CONTROL, access_result=AccessResult.DENIED)
    result = check_denied_control(observation)
    assert result.status == PredicateStatus.SATISFIED


def test_denied_control_unsatisfied_when_unauthorized_identity_can_read():
    observation = _observation(role=ObservationRole.DENIED_CONTROL, access_result=AccessResult.GRANTED)
    result = check_denied_control(observation)
    assert result.status == PredicateStatus.UNSATISFIED


def test_denied_control_insufficient_data_when_access_result_ambiguous():
    observation = _observation(role=ObservationRole.DENIED_CONTROL, access_result=AccessResult.AMBIGUOUS)
    result = check_denied_control(observation)
    assert result.status == PredicateStatus.INSUFFICIENT_DATA


def test_denied_control_insufficient_data_when_wrong_role():
    observation = _observation(role=ObservationRole.MAIN, access_result=AccessResult.DENIED)
    result = check_denied_control(observation)
    assert result.status == PredicateStatus.INSUFFICIENT_DATA


# ----- evaluate_predicates: all 3 groups together -----


def test_evaluate_predicates_returns_all_three_groups_when_fully_satisfied():
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
    results = evaluate_predicates(observations)

    assert len(results) == 3
    by_group = {r.group: r.status for r in results}
    assert by_group["main"] == PredicateStatus.SATISFIED
    assert by_group["positive_control"] == PredicateStatus.SATISFIED
    assert by_group["denied_control"] == PredicateStatus.SATISFIED


def test_evaluate_predicates_reports_insufficient_data_for_missing_role_without_dropping_others():
    # SPEC §4.4.1: "Cả ba nhóm đều phải có kết quả trong package" — a missing
    # observation for one role must still produce a result (never silently
    # skipped), while the other two groups are unaffected.
    observations = [
        _observation(
            role=ObservationRole.MAIN,
            access_result=AccessResult.GRANTED,
            response_contains_marker=True,
            request_contains_marker=False,
        ),
        _observation(role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.GRANTED),
        # No denied_control observation at all.
    ]
    results = evaluate_predicates(observations)

    assert len(results) == 3
    by_group = {r.group: r.status for r in results}
    assert by_group["main"] == PredicateStatus.SATISFIED
    assert by_group["positive_control"] == PredicateStatus.SATISFIED
    assert by_group["denied_control"] == PredicateStatus.INSUFFICIENT_DATA


def test_evaluate_predicates_with_no_observations_at_all_is_all_insufficient_data():
    results = evaluate_predicates([])
    assert len(results) == 3
    assert all(r.status == PredicateStatus.INSUFFICIENT_DATA for r in results)


def test_evaluate_predicates_treats_duplicate_role_as_insufficient_data_not_last_wins():
    # Regression: a dict-comprehension keyed by role used to silently keep
    # only the LAST observation for a duplicated role, discarding earlier
    # evidence that may have satisfied the predicate — a verdict flip driven
    # purely by list order. Must surface this as insufficient_data instead of
    # silently picking one.
    observations = [
        _observation(
            role=ObservationRole.MAIN,
            access_result=AccessResult.GRANTED,
            response_contains_marker=True,
            request_contains_marker=False,
        ),
        _observation(
            role=ObservationRole.MAIN,
            access_result=AccessResult.GRANTED,
            response_contains_marker=False,
            request_contains_marker=False,
        ),
        _observation(role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.GRANTED),
        _observation(role=ObservationRole.DENIED_CONTROL, access_result=AccessResult.DENIED),
    ]
    results = evaluate_predicates(observations)

    by_group = {r.group: r.status for r in results}
    assert by_group["main"] == PredicateStatus.INSUFFICIENT_DATA
    assert by_group["positive_control"] == PredicateStatus.SATISFIED
    assert by_group["denied_control"] == PredicateStatus.SATISFIED
