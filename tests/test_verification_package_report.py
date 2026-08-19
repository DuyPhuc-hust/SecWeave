from datetime import datetime, timezone

from shared.models.action import ActionSpec, ActionType
from shared.models.observation import (
    AccessResult,
    EvidenceChannel,
    NormalizedObservation,
    ObservationRole,
    PredicateResult,
    PredicateStatus,
    Verdict,
)
from shared.models.verification_package import (
    Environment,
    HumanReviewRecord,
    ReviewDecision,
    VerificationPackage,
)
from verification_package.report import render_markdown_report


def _action(action_id: str, role: ObservationRole, target: str, description: str, **overrides) -> ActionSpec:
    return ActionSpec(
        action_id=action_id,
        type=ActionType.READ_ONLY,
        method=overrides.pop("method", "GET"),
        target=target,
        description=description,
        role=role,
        **overrides,
    )


def _observation(action_ref: str, role: ObservationRole, **overrides) -> NormalizedObservation:
    defaults = dict(
        observation_id=f"obs_{action_ref}",
        action_ref=action_ref,
        role=role,
        captured_at=datetime(2026, 8, 19, tzinfo=timezone.utc),
        identity="attacker",
        execution_id="exec_1",
        target_id="tgt_1",
        target_revision_id="rev_1",
        channel=EvidenceChannel.HTTP_TRANSACTION,
        raw_evidence_size_bytes=512,
        raw_evidence_hash="sha256:aaa",
        raw_evidence_ref="/tmp/obs.json",
        access_result=AccessResult.GRANTED,
    )
    defaults.update(overrides)
    return NormalizedObservation(**defaults)


def _confirmed_package(**overrides) -> VerificationPackage:
    actions = [
        _action("act_main", ObservationRole.MAIN, "https://staging.example.com/api/objects/42", "Main read."),
        _action(
            "act_pos",
            ObservationRole.POSITIVE_CONTROL,
            "https://staging.example.com/api/objects/1",
            "Owner reads own object.",
        ),
        _action(
            "act_denied",
            ObservationRole.DENIED_CONTROL,
            "https://staging.example.com/api/objects/1",
            "Stranger denied.",
        ),
    ]
    observations = [
        _observation("act_main", ObservationRole.MAIN, response_contains_marker=True, request_contains_marker=False),
        _observation("act_pos", ObservationRole.POSITIVE_CONTROL, identity="owner"),
        _observation(
            "act_denied",
            ObservationRole.DENIED_CONTROL,
            identity="stranger",
            access_result=AccessResult.DENIED,
            status_code=401,
        ),
    ]
    defaults = dict(
        package_id="pkg_1",
        target_id="tgt_1",
        environment=Environment.STAGING,
        revision="rev_1",
        authorization_reference="auth_1",
        scenario="IDOR on /api/objects/{id}",
        identities=["owner", "attacker", "stranger"],
        execution_id="exec_1",
        action_record=actions,
        raw_evidence_references=[o.raw_evidence_ref for o in observations],
        artifact_hashes=[o.raw_evidence_hash for o in observations],
        normalized_observations=observations,
        oracle_rule_version="v1-draft",
        predicate_results=[
            PredicateResult(group=ObservationRole.MAIN, status=PredicateStatus.SATISFIED, reason="Marker leaked."),
            PredicateResult(
                group=ObservationRole.POSITIVE_CONTROL, status=PredicateStatus.SATISFIED, reason="Owner could read."
            ),
            PredicateResult(
                group=ObservationRole.DENIED_CONTROL, status=PredicateStatus.SATISFIED, reason="Stranger denied."
            ),
        ],
        verdict=Verdict.CONFIRMED,
        verdict_reason="All 3 predicate groups satisfied.",
        limitations="Only 1 object tested; no retest yet.",
        next_action="Notify the system owner.",
    )
    defaults.update(overrides)
    return VerificationPackage(**defaults)


def test_render_markdown_report_includes_every_spec_field():
    package = _confirmed_package(
        human_review_record=HumanReviewRecord(
            reviewer="qa1",
            reviewed_at=datetime(2026, 8, 19, tzinfo=timezone.utc),
            decision=ReviewDecision.RELEASE,
            reason="Checked raw evidence, marker confirmed.",
            checked_raw_artifact=True,
        ),
        retest_reference="retest_run_1",
    )
    report = render_markdown_report(package)

    assert "pkg_1" in report
    assert "CONFIRMED" in report
    assert "tgt_1" in report
    assert "staging" in report
    assert "rev_1" in report
    assert "IDOR on /api/objects/{id}" in report
    assert "exec_1" in report
    assert "v1-draft" in report
    assert "auth_1" in report
    assert "owner" in report and "attacker" in report and "stranger" in report
    assert "Marker leaked." in report
    assert "Owner reads own object." in report
    assert "sha256:aaa" in report
    assert "qa1" in report
    assert "Checked raw evidence, marker confirmed." in report
    assert "retest_run_1" in report
    assert "Notify the system owner." in report
    assert "Only 1 object tested; no retest yet." in report
    assert "Đủ điều kiện phát hành" in report


def test_render_markdown_report_shows_release_candidate_note_when_not_yet_reviewed():
    package = _confirmed_package()  # human_review_record=None, retest_reference=None by default
    report = render_markdown_report(package)

    assert "release candidate, chưa qua Gate 4" in report
    assert "Chưa có retest nào tham chiếu." in report
    assert "Chưa đủ điều kiện phát hành" in report
    assert "human_review_record" in report
    assert "retest_reference" in report


def test_render_markdown_report_shows_placeholder_when_predicate_results_is_empty():
    action = _action("act_main", ObservationRole.MAIN, "https://staging.example.com/x", "read")
    observation = _observation("act_main", ObservationRole.MAIN)
    package = VerificationPackage(
        package_id="pkg_2",
        target_id="tgt_1",
        environment=Environment.STAGING,
        revision="rev_1",
        authorization_reference="auth_1",
        scenario="s",
        identities=["attacker"],
        execution_id="exec_1",
        action_record=[action],
        raw_evidence_references=[observation.raw_evidence_ref],
        artifact_hashes=[observation.raw_evidence_hash],
        normalized_observations=[observation],
        oracle_rule_version="v1-draft",
        predicate_results=[],
        verdict=Verdict.INCONCLUSIVE,
        verdict_reason="Execution stopped early.",
        limitations="l",
        next_action="n",
    )
    report = render_markdown_report(package)
    assert "không có predicate result nào" in report


def test_render_markdown_report_escapes_pipe_characters_so_table_rows_stay_intact():
    # A `|` in a free-text field (an LLM-authored description, a URL query
    # string) would otherwise silently split a Markdown table row into 2
    # misaligned cells — every free-text table cell must escape it.
    package = _confirmed_package(
        scenario="s",
    )
    package.action_record[0].description = "Reads object 42 | also probes ?debug=1|2"
    report = render_markdown_report(package)
    assert "Reads object 42 \\| also probes ?debug=1\\|2" in report
    assert "Reads object 42 | also probes ?debug=1|2" not in report


def test_render_markdown_report_shows_action_record_caveat_about_unredacted_parameters():
    package = _confirmed_package()
    package.action_record[0].parameters = {"password": "hunter2"}
    report = render_markdown_report(package)
    assert "hunter2" in report  # deliberately NOT redacted — see report.py's docstring
    assert "giữ nguyên giá trị THẬT" in report


def test_render_markdown_report_puts_limitations_before_action_record():
    # SPEC field #17's own wording: "trường nên đọc đầu tiên."
    package = _confirmed_package()
    report = render_markdown_report(package)
    assert report.index("Limitations") < report.index("Action record")


def test_render_markdown_report_escapes_a_pipe_in_action_method():
    # Real gap found via independent review: `action.method` was the only
    # cell in the action_record row NOT passed through `_escape_cell` —
    # target/description/parameters right next to it all were. `method` is
    # an unconstrained str (shared/models/action.py), so an LLM-authored or
    # hand-crafted plan can put anything there.
    package = _confirmed_package()
    package.action_record[0].method = "GET | rm -rf /"
    report = render_markdown_report(package)
    assert "GET \\| rm -rf /" in report
    assert "| GET | rm -rf / |" not in report


def test_render_markdown_report_escapes_a_pipe_and_backtick_in_raw_evidence_hash():
    # Real gap found via independent review: raw_evidence_hash was wrapped
    # in a raw backtick code span with no `_escape_cell` — a backtick in
    # the value closes the span early, and (like every other cell) an
    # unescaped `|` also splits the table row.
    package = _confirmed_package()
    tampered_hash = "sha256:abc`|evil"
    package.normalized_observations[0].raw_evidence_hash = tampered_hash
    package.artifact_hashes[0] = tampered_hash
    report = render_markdown_report(package)
    assert "sha256:abc`\\|evil" in report
    assert "`sha256:abc`" not in report  # no raw code span wrapping the tampered value anymore
