"""Verification Package — SPEC §7's 19-field output contract, this
project's actual deliverable ("hợp đồng đầu ra của toàn hệ thống"). SPEC:
"Package hợp lệ phải có đủ 19 trường; thiếu trường bắt buộc → không được
phát hành" — but "phát hành" (release) happens at Gate 4 (§4.5), AFTER
this object is first assembled. SPEC §4.5 itself distinguishes a "release
candidate" (assembled, awaiting review) from a released package: "Tại
Gate 4, người review/releaser nhận release candidate ... hoặc execution
record (để xác nhận vì sao chưa thể tạo package)." So this model allows
2 of the 19 fields (human_review_record, retest_reference) to be
genuinely absent on a freshly-assembled candidate — they cannot exist yet
by construction (no Gate 4 review has happened, no retest has run) — and
provides `missing_fields_for_release()` to check the actual SPEC
completeness gate (all 19 present) separately from "does this object
exist at all." This is deliberately NOT the same thing as ECS (Evidence
Completeness Score, §8.1) — ECS is a quality rubric with a threshold
still Proposed/TBD; this is pure binary schema completeness, no scoring.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from shared.models.action import ActionSpec
from shared.models.observation import (
    REQUIRED_PREDICATE_GROUPS,
    NormalizedObservation,
    PredicateResult,
    PredicateStatus,
    Verdict,
    predicate_results_cover_all_required_groups,
)


class Environment(str, Enum):
    """SPEC §7 field #3's own wording: "staging / sandbox" — a closed set,
    matching NX-GO-02's hard requirement that a target never be production.
    """

    STAGING = "staging"
    SANDBOX = "sandbox"


class ReviewDecision(str, Enum):
    """SPEC §4.5's 3 outcomes a Gate 4 reviewer can reach for one package."""

    RELEASE = "release"
    RETEST = "retest"
    REJECT = "reject"


class HumanReviewRecord(BaseModel):
    """Field #16 — "Người review, thời điểm, quyết định, lý do." SPEC §4.5
    requires the reviewer to have personally cross-checked >=1 raw
    artifact against its normalized observation, not just read an AI-
    written summary — `checked_raw_artifact` records that this actually
    happened, so a package can't claim a real review occurred without it.
    """

    reviewer: str
    reviewed_at: datetime
    decision: ReviewDecision
    reason: str
    checked_raw_artifact: bool

    @field_validator("reviewed_at")
    @classmethod
    def _require_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError(
                "reviewed_at phải có timezone — thiếu timezone dễ bị hiểu nhầm giữa giờ địa phương "
                "và UTC khi đối chiếu audit log."
            )
        return value

    @model_validator(mode="after")
    def _check_release_requires_checked_raw_artifact(self) -> "HumanReviewRecord":
        # Defense-in-depth, added alongside `secweave review-package`:
        # VerificationPackage.missing_fields_for_release() already checks
        # this at the OUTER model (decision must be RELEASE AND
        # checked_raw_artifact must be True for is_release_ready), so this
        # isn't closing a live bypass today — but HumanReviewRecord is a
        # standalone model that could be constructed/reused outside a full
        # VerificationPackage in the future, and this project's established
        # pattern is that every safety-critical model validates its own
        # invariant independently rather than relying solely on an outer
        # caller to have done so (see VerdictResult/VerificationPackage's
        # own predicate-completeness checks for the same reasoning).
        # SPEC §4.5: releasing requires having personally cross-checked
        # >=1 raw artifact — a decision=RELEASE record that never set this
        # is a contradiction in terms, not a valid record of what happened.
        if self.decision == ReviewDecision.RELEASE and not self.checked_raw_artifact:
            raise ValueError(
                "decision=release yêu cầu checked_raw_artifact=true — SPEC §4.5: người review phải "
                "tự tay đối chiếu ít nhất 1 raw artifact trước khi phát hành, không chỉ đọc tóm tắt."
            )
        return self


class VerificationPackage(BaseModel):
    """SPEC §7's 19 fields, verbatim order. Field numbers in comments match
    the SPEC table exactly, so a reviewer can check this model against the
    doc line by line without re-deriving a mapping.
    """

    package_id: str  # 1. Package ID
    target_id: str  # 2. Target
    environment: Environment  # 3. Environment
    revision: str  # 4. Revision (target_revision_id)
    authorization_reference: str  # 5. Authorization reference
    # Real gap found via independent review: this required-judgment field
    # was missing the min_length=1 constraint its siblings (verdict_reason/
    # limitations/next_action, below) all have — an empty scenario silently
    # passed straight through, including via `secweave assemble-package`'s
    # --scenario flag (itself deliberately required with no CLI-level
    # emptiness check either, relying on this model to be the real gate).
    scenario: str = Field(min_length=1)  # 6. Scenario
    identities: List[str] = Field(min_length=1)  # 7. Identity (plural — a real run needs >=2 to have
    # a meaningful positive_control/denied_control pair; SPEC names this
    # field singular but this codebase's own Evidence Harness already
    # requires multiple real identities per run to test anything real, so a
    # single-identity list would misrepresent what a real run actually used.
    # Real gap found via independent review: this is a flat, undifferentiated
    # list — it does NOT distinguish which identity played which role (the
    # attacker/main identity, the positive_control owner, or a pure SETUP/
    # infrastructure identity like a seed-data bot account), so a reader
    # can't tell "3 identities were used in the privilege test itself" from
    # "2 were, plus 1 was just a login helper." Not fixed in this increment
    # — SPEC's own field #7 is a single unstructured value, and giving it
    # real per-role structure is a bigger schema change than this pass
    # attempts; flagged here so a future revision knows to scrutinize it.)
    execution_id: str  # 8. Execution ID
    action_record: List[ActionSpec] = Field(min_length=1)  # 9. Action record
    raw_evidence_references: List[str] = Field(min_length=1)  # 10. Raw evidence references
    artifact_hashes: List[str] = Field(min_length=1)  # 11. Artifact hash (per-artifact, same order/length as
    # raw_evidence_references — see the assembler for how these two stay
    # paired instead of just being 2 independently-populated lists)
    normalized_observations: List[NormalizedObservation] = Field(min_length=1)  # 12. Normalized observation
    oracle_rule_version: str  # 13. Oracle rule / version
    predicate_results: List[PredicateResult]  # 14. Predicate results
    verdict: Verdict  # 15. Verification verdict
    verdict_reason: str = Field(min_length=1)  # 15 (cont'd) — real gap found via independent review:
    # verdict alone can't explain an unusual-looking but CORRECT combination
    # (e.g. all 3 predicate groups SATISFIED yet verdict=INCONCLUSIVE because
    # execution_status wasn't COMPLETED) — that explanation lives ONLY in
    # VerdictResult.reason (verdict_oracle/oracle.py), which the assembler
    # used to silently discard. VerdictResult's OWN docstring states the
    # traceability principle this violated: "a human reviewer... never has
    # to re-derive why this verdict was reached from a separate lookup."
    human_review_record: Optional[HumanReviewRecord] = None  # 16. Human-review record (absent until Gate 4)
    limitations: str = Field(min_length=1)  # 17. Limitations — SPEC: "nên đọc đầu tiên", must never be
    # empty; an empty string would silently claim "nothing this package
    # doesn't prove," which is never true for a real verification
    next_action: str = Field(min_length=1)  # 18. Next action
    retest_reference: Optional[str] = None  # 19. Retest reference (absent until retests have run)

    @model_validator(mode="after")
    def _evidence_references_and_hashes_must_match_observations(self) -> "VerificationPackage":
        # Real gap found via independent review: the original version of
        # this check only compared LENGTHS, which let raw_evidence_references
        # and artifact_hashes be positionally SWAPPED relative to each other
        # (or relative to normalized_observations, which already carries the
        # authoritative raw_evidence_ref/raw_evidence_hash per observation —
        # 3 redundant sources of truth, one weak check) — a reviewer trusting
        # artifact_hashes[i] to verify raw_evidence_references[i]'s integrity
        # (the entire point of SPEC field #11) would silently check the
        # wrong hash against the wrong file. Now requires EXACT equality
        # (same values, same order) against what normalized_observations
        # itself says — the two fields carry no information independent of
        # field #12, they exist only because SPEC names them separately.
        expected_refs = [o.raw_evidence_ref for o in self.normalized_observations]
        expected_hashes = [o.raw_evidence_hash for o in self.normalized_observations]
        if self.raw_evidence_references != expected_refs or self.artifact_hashes != expected_hashes:
            raise ValueError(
                "raw_evidence_references/artifact_hashes phải khớp CHÍNH XÁC (đúng giá trị, đúng thứ "
                "tự) với raw_evidence_ref/raw_evidence_hash lấy từ normalized_observations — không "
                "được để 2 trường này trôi khỏi nguồn dữ liệu gốc mà chúng chỉ đơn thuần trích ra."
            )
        return self

    @model_validator(mode="after")
    def _action_record_must_be_unique_and_cover_every_executed_action(self) -> "VerificationPackage":
        # Real gap found via independent review, 2 distinct failure modes:
        # (1) action_record used to be built by filtering a caller's action
        #     list to matching IDs with no check that EVERY action_ref
        #     actually appearing in normalized_observations had a match —
        #     a caller passing an incomplete `actions` list produced a
        #     package that looked complete (min_length=1 satisfied) while
        #     silently missing the ActionSpecs a CONFIRMED verdict actually
        #     rested on, directly undermining field #9's stated purpose
        #     ("đủ để lặp lại" — sufficient to reproduce).
        # (2) two different ActionSpecs sharing the same action_id (nothing
        #     enforces uniqueness upstream) produced duplicate, AMBIGUOUS
        #     entries for what was really one executed action.
        action_ids = [action.action_id for action in self.action_record]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError(
                "action_record chứa action_id trùng lặp — mỗi hành động đã thực thi chỉ được có "
                "đúng 1 ActionSpec, không được mơ hồ giữa 2 bản khác nhau cùng 1 ID."
            )
        executed_action_ids = {observation.action_ref for observation in self.normalized_observations}
        missing = executed_action_ids - set(action_ids)
        if missing:
            raise ValueError(
                f"action_record thiếu ActionSpec cho action_ref: {sorted(missing)} — mọi hành động "
                "thực sự tạo ra observation phải có mặt trong action_record để package còn 'đủ để "
                "lặp lại' (SPEC §7 trường #9)."
            )
        return self

    @model_validator(mode="after")
    def _check_confirmed_requires_all_groups_satisfied(self) -> "VerificationPackage":
        # Real gap found via independent review: VerdictResult (shared/
        # models/observation.py) already has this exact check, since
        # verdict/predicate_results independently constructible-out-of-sync
        # is the one failure SPEC treats as never acceptable ("thiếu
        # positive control thì không có CONFIRMED, không ngoại lệ"). But
        # VerificationPackage stores verdict/predicate_results as its OWN
        # 2 separate fields (matching SPEC's field-by-field layout, #14/#15)
        # rather than embedding a VerdictResult, so that protection was
        # lost here — anything constructing/reloading a package directly
        # (not only through the assembler, which always derives both from
        # one real VerdictResult) had no independent check at all. Same
        # ONE-DIRECTIONAL reasoning as VerdictResult's own validator: a
        # verdict=INCONCLUSIVE package can legitimately have all 3 groups
        # SATISFIED (the execution_status gate overrides), so only the
        # CONFIRMED direction is checked.
        if self.verdict == Verdict.CONFIRMED and not all(
            r.status == PredicateStatus.SATISFIED for r in self.predicate_results
        ):
            raise ValueError(
                "verdict=confirmed yêu cầu CẢ 3 nhóm predicate đều satisfied — không được set "
                "verdict=confirmed khi predicate_results không thực sự chứng minh điều đó."
            )
        return self

    @model_validator(mode="after")
    def _check_predicate_results_cover_all_required_groups(self) -> "VerificationPackage":
        # See predicate_results_cover_all_required_groups()'s docstring for
        # why this check exists. Scoped to CONFIRMED only (unlike
        # VerdictResult's unconditional version) because an existing,
        # deliberate test (test_package_allows_inconclusive_verdict_even_
        # when_predicate_results_is_empty) establishes that a non-CONFIRMED
        # package may legitimately have incomplete/empty predicate_results
        # (e.g. a run stopped before any observation existed).
        if self.verdict == Verdict.CONFIRMED and not predicate_results_cover_all_required_groups(
            self.predicate_results
        ):
            raise ValueError(
                f"verdict=confirmed yêu cầu đúng 1 kết quả cho mỗi nhóm bắt buộc "
                f"{sorted(g.value for g in REQUIRED_PREDICATE_GROUPS)} — nhận được: "
                f"{sorted(r.group.value for r in self.predicate_results)}."
            )
        return self

    def missing_fields_for_release(self) -> List[str]:
        """SPEC §7/§8.1's actual release gate ("Binary schema completeness
        ... không quy đổi thành điểm; thiếu → không release"). Checks not
        just PRESENCE of human_review_record/retest_reference (the 2 fields
        a freshly-assembled candidate is allowed to still be missing) but
        also the CONTENT of human_review_record — real gap found via
        independent review: the original version only checked "is this
        field non-None," so a package where the reviewer explicitly chose
        decision=REJECT, or never actually set checked_raw_artifact=True
        (SPEC §4.5's own requirement that a real review means personally
        cross-checking >=1 raw artifact, not just reading an AI summary),
        still reported is_release_ready=True — the exact opposite of what
        a human's own recorded decision said.
        """
        missing = []
        if self.human_review_record is None:
            missing.append("human_review_record")
        elif self.human_review_record.decision != ReviewDecision.RELEASE:
            missing.append(
                f"human_review_record.decision (hiện tại: "
                f"'{self.human_review_record.decision.value}', cần 'release')"
            )
        elif not self.human_review_record.checked_raw_artifact:
            missing.append(
                "human_review_record.checked_raw_artifact (reviewer chưa xác nhận đã tự tay đối "
                "chiếu raw artifact — SPEC §4.5)"
            )
        if self.retest_reference is None:
            missing.append("retest_reference")
        return missing

    @property
    def is_release_ready(self) -> bool:
        return not self.missing_fields_for_release()
