import hashlib
import itertools
from datetime import datetime, timezone
from pathlib import Path

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
    # raw_evidence_hash/raw_evidence_ref here are placeholders that never get
    # read from disk — safe for the check_main_predicate/check_positive_
    # control/check_denied_control tests below, which call those functions
    # DIRECTLY and never go through evaluate_predicates()'s hash check (see
    # _hash_mismatch_reason in predicates.py). The evaluate_predicates()
    # tests further down use _observation_with_real_evidence() instead,
    # since THAT code path does read the file back and verify the hash.
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


_artifact_counter = itertools.count()


def _observation_with_real_evidence(tmp_path, **overrides) -> NormalizedObservation:
    """Like _observation(), but writes a REAL file to tmp_path and computes
    its REAL hash — for tests that go through evaluate_predicates(), which
    (since the hash-mismatch fix) actually reads raw_evidence_ref back and
    recomputes the hash, unlike the individual check_*_predicate functions.
    """
    content = overrides.pop("raw_evidence_content", b"real evidence bytes")
    artifact_path = tmp_path / f"artifact_{next(_artifact_counter)}.json"
    artifact_path.write_bytes(content)
    overrides["raw_evidence_hash"] = "sha256:" + hashlib.sha256(content).hexdigest()
    overrides["raw_evidence_ref"] = str(artifact_path)
    return _observation(**overrides)


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


def test_evaluate_predicates_returns_all_three_groups_when_fully_satisfied(tmp_path):
    observations = [
        _observation_with_real_evidence(
            tmp_path,
            role=ObservationRole.MAIN,
            access_result=AccessResult.GRANTED,
            response_contains_marker=True,
            request_contains_marker=False,
        ),
        _observation_with_real_evidence(
            tmp_path, role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.GRANTED
        ),
        _observation_with_real_evidence(
            tmp_path, role=ObservationRole.DENIED_CONTROL, access_result=AccessResult.DENIED
        ),
    ]
    results = evaluate_predicates(observations)

    assert len(results) == 3
    by_group = {r.group: r.status for r in results}
    assert by_group["main"] == PredicateStatus.SATISFIED
    assert by_group["positive_control"] == PredicateStatus.SATISFIED
    assert by_group["denied_control"] == PredicateStatus.SATISFIED


def test_evaluate_predicates_reports_insufficient_data_for_missing_role_without_dropping_others(tmp_path):
    # SPEC §4.4.1: "Cả ba nhóm đều phải có kết quả trong package" — a missing
    # observation for one role must still produce a result (never silently
    # skipped), while the other two groups are unaffected.
    observations = [
        _observation_with_real_evidence(
            tmp_path,
            role=ObservationRole.MAIN,
            access_result=AccessResult.GRANTED,
            response_contains_marker=True,
            request_contains_marker=False,
        ),
        _observation_with_real_evidence(
            tmp_path, role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.GRANTED
        ),
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


def test_evaluate_predicates_treats_duplicate_role_as_insufficient_data_not_last_wins(tmp_path):
    # Regression: a dict-comprehension keyed by role used to silently keep
    # only the LAST observation for a duplicated role, discarding earlier
    # evidence that may have satisfied the predicate — a verdict flip driven
    # purely by list order. Must surface this as insufficient_data instead of
    # silently picking one.
    observations = [
        _observation_with_real_evidence(
            tmp_path,
            role=ObservationRole.MAIN,
            access_result=AccessResult.GRANTED,
            response_contains_marker=True,
            request_contains_marker=False,
        ),
        _observation_with_real_evidence(
            tmp_path,
            role=ObservationRole.MAIN,
            access_result=AccessResult.GRANTED,
            response_contains_marker=False,
            request_contains_marker=False,
        ),
        _observation_with_real_evidence(
            tmp_path, role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.GRANTED
        ),
        _observation_with_real_evidence(
            tmp_path, role=ObservationRole.DENIED_CONTROL, access_result=AccessResult.DENIED
        ),
    ]
    results = evaluate_predicates(observations)

    by_group = {r.group: r.status for r in results}
    assert by_group["main"] == PredicateStatus.INSUFFICIENT_DATA
    assert by_group["positive_control"] == PredicateStatus.SATISFIED
    assert by_group["denied_control"] == PredicateStatus.SATISFIED


# ----- Hash verification (SPEC §6.4 control #8) -----


def test_evaluate_predicates_treats_hash_mismatch_as_insufficient_data(tmp_path):
    observation = _observation_with_real_evidence(
        tmp_path, role=ObservationRole.POSITIVE_CONTROL, access_result=AccessResult.GRANTED
    )
    # Tamper with the artifact AFTER its hash was computed and stored on the
    # observation — simulates evidence being modified post-capture.
    Path(observation.raw_evidence_ref).write_bytes(b"tampered content")

    results = evaluate_predicates([observation])
    by_group = {r.group: r.status for r in results}
    assert by_group["positive_control"] == PredicateStatus.INSUFFICIENT_DATA
    reason = next(r.reason for r in results if r.group == ObservationRole.POSITIVE_CONTROL)
    assert "Hash không khớp" in reason


def test_evaluate_predicates_treats_missing_raw_evidence_file_as_insufficient_data(tmp_path):
    observation = _observation_with_real_evidence(
        tmp_path, role=ObservationRole.DENIED_CONTROL, access_result=AccessResult.DENIED
    )
    Path(observation.raw_evidence_ref).unlink()  # simulates a lost/deleted artifact

    results = evaluate_predicates([observation])
    by_group = {r.group: r.status for r in results}
    assert by_group["denied_control"] == PredicateStatus.INSUFFICIENT_DATA
    reason = next(r.reason for r in results if r.group == ObservationRole.DENIED_CONTROL)
    assert "Không đọc được raw evidence" in reason
