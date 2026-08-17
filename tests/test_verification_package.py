import hashlib
import itertools
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from shared.models.action import ActionSpec, ActionType
from shared.models.entities import Authorization, AuthorizationLayer
from shared.models.kill_switch import ExecutionStatus
from shared.models.observation import AccessResult, EvidenceChannel, NormalizedObservation, ObservationRole, Verdict
from shared.models.verification_package import (
    Environment,
    HumanReviewRecord,
    ReviewDecision,
    VerificationPackage,
)
from verification_package.assembler import assemble_verification_package


def _action(action_id: str, target: str = "https://staging.example.com/api/objects/42") -> ActionSpec:
    return ActionSpec(
        action_id=action_id,
        type=ActionType.READ_ONLY,
        method="GET",
        target=target,
        description="Read object 42.",
    )


def _observation(**overrides) -> NormalizedObservation:
    defaults = dict(
        observation_id="obs_1",
        action_ref="act_main",
        role=ObservationRole.MAIN,
        captured_at=datetime(2026, 8, 17, tzinfo=timezone.utc),
        identity="attacker",
        execution_id="exec_1",
        target_id="tgt_1",
        target_revision_id="rev_1",
        channel=EvidenceChannel.HTTP_TRANSACTION,
        raw_evidence_size_bytes=512,
        raw_evidence_hash="sha256:aaa",
        raw_evidence_ref="/tmp/obs_1.json",
        access_result=AccessResult.GRANTED,
    )
    defaults.update(overrides)
    return NormalizedObservation(**defaults)


def _authorization() -> Authorization:
    return Authorization(
        id="auth_1",
        layer=AuthorizationLayer.TARGET_AUTHORIZATION,
        approved_by="owner",
        approved_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )


def _base_package_kwargs(**overrides) -> dict:
    defaults = dict(
        package_id="pkg_1",
        target_id="tgt_1",
        environment=Environment.STAGING,
        revision="rev_1",
        authorization_reference="auth_1",
        scenario="IDOR on /api/objects/{id}",
        identities=["owner", "attacker"],
        execution_id="exec_1",
        action_record=[_action("act_main")],
        raw_evidence_references=["/tmp/obs_1.json"],
        artifact_hashes=["sha256:aaa"],
        normalized_observations=[_observation()],
        oracle_rule_version="v1-draft",
        predicate_results=[],
        verdict=Verdict.INCONCLUSIVE,
        limitations="Only the main predicate was evaluated in this fixture.",
        next_action="N/A — test fixture.",
    )
    defaults.update(overrides)
    return defaults


# ----- VerificationPackage model -----


def test_package_constructs_with_all_required_fields():
    package = VerificationPackage(**_base_package_kwargs())
    assert package.package_id == "pkg_1"


def test_package_missing_2_optional_fields_is_not_release_ready():
    package = VerificationPackage(**_base_package_kwargs())
    assert package.is_release_ready is False
    assert set(package.missing_fields_for_release()) == {"human_review_record", "retest_reference"}


def test_package_with_only_human_review_still_missing_retest():
    package = VerificationPackage(
        **_base_package_kwargs(
            human_review_record=HumanReviewRecord(
                reviewer="reviewer@secweave.local",
                reviewed_at=datetime(2026, 8, 18, tzinfo=timezone.utc),
                decision=ReviewDecision.RETEST,
                reason="Need 3 retest runs before release.",
                checked_raw_artifact=True,
            )
        )
    )
    assert package.missing_fields_for_release() == ["retest_reference"]
    assert package.is_release_ready is False


def test_package_with_both_fields_is_release_ready():
    package = VerificationPackage(
        **_base_package_kwargs(
            human_review_record=HumanReviewRecord(
                reviewer="reviewer@secweave.local",
                reviewed_at=datetime(2026, 8, 18, tzinfo=timezone.utc),
                decision=ReviewDecision.RELEASE,
                reason="3/3 retests agree, raw artifact checked.",
                checked_raw_artifact=True,
            ),
            retest_reference="retest_run_1,retest_run_2,retest_run_3",
        )
    )
    assert package.missing_fields_for_release() == []
    assert package.is_release_ready is True


def test_package_rejects_empty_limitations():
    with pytest.raises(ValidationError):
        VerificationPackage(**_base_package_kwargs(limitations=""))


def test_package_rejects_empty_next_action():
    with pytest.raises(ValidationError):
        VerificationPackage(**_base_package_kwargs(next_action=""))


@pytest.mark.parametrize(
    "field",
    ["identities", "action_record", "raw_evidence_references", "artifact_hashes", "normalized_observations"],
)
def test_package_rejects_empty_lists_for_required_evidence_fields(field):
    with pytest.raises(ValidationError):
        VerificationPackage(**_base_package_kwargs(**{field: []}))


def test_package_rejects_mismatched_evidence_reference_and_hash_lengths():
    # Real gap this closes: raw_evidence_references and artifact_hashes are
    # positionally paired — nothing else in the model enforces this, so a
    # caller passing out-of-sync lists would silently misattribute a hash
    # to the wrong artifact for every index past the shorter list's end.
    with pytest.raises(ValidationError):
        VerificationPackage(
            **_base_package_kwargs(
                raw_evidence_references=["/tmp/obs_1.json", "/tmp/obs_2.json"],
                artifact_hashes=["sha256:aaa"],
            )
        )


def test_human_review_record_rejects_timezone_naive_reviewed_at():
    with pytest.raises(ValidationError):
        HumanReviewRecord(
            reviewer="reviewer@secweave.local",
            reviewed_at=datetime(2026, 8, 18),  # naive
            decision=ReviewDecision.RELEASE,
            reason="x",
            checked_raw_artifact=True,
        )


# ----- assemble_verification_package() -----
#
# evaluate_predicates() (inside decide(), called by the assembler) actually
# reads raw_evidence_ref back off disk and recomputes its hash (SPEC §6.4
# control #8) — so every observation fed through the assembler needs a REAL
# file with a hash that actually matches, not the placeholder paths/hashes
# _observation() above uses (those are fine for the pure-model tests above,
# which never touch decide()).

_artifact_counter = itertools.count()


def _observation_with_real_evidence(tmp_path, **overrides) -> NormalizedObservation:
    content = overrides.pop("raw_evidence_content", b"real evidence bytes")
    artifact_path = tmp_path / f"artifact_{next(_artifact_counter)}.json"
    artifact_path.write_bytes(content)
    overrides["raw_evidence_hash"] = "sha256:" + hashlib.sha256(content).hexdigest()
    overrides["raw_evidence_ref"] = str(artifact_path)
    return _observation(**overrides)


def _three_role_observations(tmp_path, *, denied_status: AccessResult = AccessResult.DENIED) -> list:
    return [
        _observation_with_real_evidence(
            tmp_path,
            observation_id="obs_main",
            action_ref="act_main",
            role=ObservationRole.MAIN,
            identity="attacker",
            access_result=AccessResult.GRANTED,
            response_contains_marker=True,
            request_contains_marker=False,
        ),
        _observation_with_real_evidence(
            tmp_path,
            observation_id="obs_positive",
            action_ref="act_positive",
            role=ObservationRole.POSITIVE_CONTROL,
            identity="owner",
            access_result=AccessResult.GRANTED,
        ),
        _observation_with_real_evidence(
            tmp_path,
            observation_id="obs_denied",
            action_ref="act_denied",
            role=ObservationRole.DENIED_CONTROL,
            identity="attacker",
            access_result=denied_status,
        ),
    ]


def test_assemble_produces_confirmed_package_from_a_full_satisfied_run(tmp_path):
    observations = _three_role_observations(tmp_path)
    actions = [_action("act_main"), _action("act_positive"), _action("act_denied")]

    package = assemble_verification_package(
        target_id="tgt_1",
        environment=Environment.STAGING,
        revision="rev_1",
        authorization=_authorization(),
        scenario="IDOR on /api/objects/42",
        execution_id="exec_1",
        actions=actions,
        observations=observations,
        execution_status=ExecutionStatus.COMPLETED,
        limitations="Only tested against 2 identities; not a full authz audit.",
        next_action="Send finding to system owner per A.html §9.9.",
    )

    assert package.verdict == Verdict.CONFIRMED
    assert package.identities == ["attacker", "owner"]  # deduplicated, sorted
    assert len(package.action_record) == 3
    assert len(package.normalized_observations) == 3
    assert package.raw_evidence_references == [o.raw_evidence_ref for o in observations]
    assert package.artifact_hashes == [o.raw_evidence_hash for o in observations]
    assert package.oracle_rule_version  # non-empty, sourced from predicates.py
    assert package.human_review_record is None  # no Gate 4 review has happened yet
    assert package.is_release_ready is False


def test_assemble_excludes_planned_but_never_executed_actions_from_action_record(tmp_path):
    # A 4th action exists in the plan but has no corresponding observation
    # (e.g. the run was stopped before it executed) — it must NOT appear in
    # action_record, which claims "what happened," not "what was planned."
    observations = _three_role_observations(tmp_path)
    actions = [
        _action("act_main"),
        _action("act_positive"),
        _action("act_denied"),
        _action("act_never_executed"),
    ]

    package = assemble_verification_package(
        target_id="tgt_1",
        environment=Environment.STAGING,
        revision="rev_1",
        authorization=_authorization(),
        scenario="IDOR on /api/objects/42",
        execution_id="exec_1",
        actions=actions,
        observations=observations,
        execution_status=ExecutionStatus.COMPLETED,
        limitations="x",
        next_action="x",
    )

    assert {a.action_id for a in package.action_record} == {"act_main", "act_positive", "act_denied"}


def test_assemble_reflects_the_real_verdict_not_just_confirmed(tmp_path):
    observations = _three_role_observations(tmp_path, denied_status=AccessResult.GRANTED)
    actions = [_action("act_main"), _action("act_positive"), _action("act_denied")]

    package = assemble_verification_package(
        target_id="tgt_1",
        environment=Environment.SANDBOX,
        revision="rev_1",
        authorization=_authorization(),
        scenario="x",
        execution_id="exec_1",
        actions=actions,
        observations=observations,
        execution_status=ExecutionStatus.COMPLETED,
        limitations="x",
        next_action="x",
    )

    assert package.verdict == Verdict.NOT_REPRODUCED


def test_assemble_still_produces_a_package_with_inconclusive_verdict_for_an_incomplete_run(tmp_path):
    # decide()/evaluate_predicates() never raises for a missing role — it
    # fills in INSUFFICIENT_DATA for whichever of the 3 required groups has
    # no observation, which assemble_verdict() then turns into a graceful
    # INCONCLUSIVE verdict. The assembler must let that flow through as a
    # normal (if unhelpful) package, not treat it as an assembly failure —
    # only a genuinely different SPEC concept ("execution record", not
    # built by this module — see assembler.py's docstring) is for runs that
    # can't produce a package at all.
    observations = [
        _observation_with_real_evidence(
            tmp_path, observation_id="obs_main", action_ref="act_main", role=ObservationRole.MAIN
        )
    ]

    package = assemble_verification_package(
        target_id="tgt_1",
        environment=Environment.STAGING,
        revision="rev_1",
        authorization=_authorization(),
        scenario="x",
        execution_id="exec_1",
        actions=[_action("act_main")],
        observations=observations,
        execution_status=ExecutionStatus.COMPLETED,
        limitations="Only the main observation was captured — no controls at all.",
        next_action="x",
    )

    assert package.verdict == Verdict.INCONCLUSIVE
    assert len(package.predicate_results) == 3  # still all 3 groups, 2 marked insufficient_data


def test_assemble_includes_setup_observations_in_action_record_but_not_predicate_results(tmp_path):
    observations = _three_role_observations(tmp_path) + [
        _observation_with_real_evidence(
            tmp_path,
            observation_id="obs_login",
            action_ref="act_login",
            role=ObservationRole.SETUP,
            identity="owner",
            access_result=AccessResult.GRANTED,
        )
    ]
    actions = [
        _action("act_main"),
        _action("act_positive"),
        _action("act_denied"),
        _action("act_login", target="https://staging.example.com/login"),
    ]

    package = assemble_verification_package(
        target_id="tgt_1",
        environment=Environment.STAGING,
        revision="rev_1",
        authorization=_authorization(),
        scenario="x",
        execution_id="exec_1",
        actions=actions,
        observations=observations,
        execution_status=ExecutionStatus.COMPLETED,
        limitations="x",
        next_action="x",
    )

    assert {a.action_id for a in package.action_record} == {
        "act_main", "act_positive", "act_denied", "act_login",
    }
    # SETUP is not one of the 3 required predicate groups, so it must never
    # show up as a 4th predicate result.
    assert len(package.predicate_results) == 3
    assert len(package.normalized_observations) == 4
