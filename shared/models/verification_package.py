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
from shared.models.observation import NormalizedObservation, PredicateResult, Verdict


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
    scenario: str  # 6. Scenario
    identities: List[str] = Field(min_length=1)  # 7. Identity (plural — a real run needs >=2 to have
    # a meaningful positive_control/denied_control pair; SPEC names this
    # field singular but this codebase's own Evidence Harness already
    # requires multiple real identities per run to test anything real, so a
    # single-identity list would misrepresent what a real run actually used)
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
    human_review_record: Optional[HumanReviewRecord] = None  # 16. Human-review record (absent until Gate 4)
    limitations: str = Field(min_length=1)  # 17. Limitations — SPEC: "nên đọc đầu tiên", must never be
    # empty; an empty string would silently claim "nothing this package
    # doesn't prove," which is never true for a real verification
    next_action: str = Field(min_length=1)  # 18. Next action
    retest_reference: Optional[str] = None  # 19. Retest reference (absent until retests have run)

    @model_validator(mode="after")
    def _artifact_hashes_length_must_match(self) -> "VerificationPackage":
        # raw_evidence_references and artifact_hashes are meant to be
        # POSITIONALLY paired (raw_evidence_references[i] <->
        # artifact_hashes[i]), same convention as NormalizedObservation's
        # own raw_evidence_ref/raw_evidence_hash pairing — a length
        # mismatch here would silently misattribute a hash to the wrong
        # artifact for every index past the shorter list's end. A plain
        # field_validator can't see a sibling field declared later in the
        # class, so this has to be a model-level check.
        if len(self.raw_evidence_references) != len(self.artifact_hashes):
            raise ValueError(
                f"raw_evidence_references ({len(self.raw_evidence_references)} phần tử) và "
                f"artifact_hashes ({len(self.artifact_hashes)} phần tử) phải cùng độ dài — 2 danh "
                "sách này ghép theo vị trí (index i của cái này khớp index i của cái kia)."
            )
        return self

    def missing_fields_for_release(self) -> List[str]:
        """SPEC §7/§8.1's actual release gate ("Binary schema completeness
        ... không quy đổi thành điểm; thiếu → không release") — checks the
        2 fields that a freshly-assembled candidate is allowed to still be
        missing. Every OTHER field is already required at construction
        time (Field(min_length=1) / a non-Optional type), so there is
        nothing else left to check here — a VerificationPackage that
        exists at all already has fields #1-15, #17-18.
        """
        missing = []
        if self.human_review_record is None:
            missing.append("human_review_record")
        if self.retest_reference is None:
            missing.append("retest_reference")
        return missing

    @property
    def is_release_ready(self) -> bool:
        return not self.missing_fields_for_release()
