from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, model_validator

from shared.models.signal import DastLocation, SastLocation, ScaLocation, SignalCoverage


class HypothesisProvenance(BaseModel):
    source_tool: str
    source_signal_id: str
    coverage: SignalCoverage
    # Keeps the original signal's location (URL for DAST, file+line for SAST,
    # package for SCA) — without this field, Exploit Agent only sees text
    # describing the behavior with no idea where to verify it, even though
    # the original signal DID have a concrete location (found via live
    # testing: all 4 real hypotheses were NOT_PLANNABLE for lack of exactly
    # this information, including the ZAP case which already had a URL in
    # its original signal).
    location: Union[SastLocation, ScaLocation, DastLocation]


class Hypothesis(BaseModel):
    hypothesis_id: str
    expected_behavior: str
    suspected_behavior: str
    observation_criteria: str
    provenance: HypothesisProvenance


class HypothesisStatus(str, Enum):
    HYPOTHESIS = "hypothesis"
    NOT_VERIFIABLE = "not_verifiable"


class HypothesisResult(BaseModel):
    status: HypothesisStatus
    hypothesis: Optional[Hypothesis] = None
    reason: Optional[str] = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "HypothesisResult":
        if self.status == HypothesisStatus.HYPOTHESIS and self.hypothesis is None:
            raise ValueError("status=hypothesis requires a hypothesis")
        if self.status == HypothesisStatus.NOT_VERIFIABLE and not self.reason:
            raise ValueError("status=not_verifiable requires a reason")
        # Real gap found via independent review: the same one-directional
        # pattern already fixed in ActionPlanResult (NOT_PLANNABLE forbids a
        # plan), PlanCheckResult, CostDecision, and PlanReviewResult — this
        # sibling model was missing its own converse check. Without it,
        # HypothesisResult(status=not_verifiable, hypothesis=<a real
        # Hypothesis>, reason="x") constructs without error: an ambiguous
        # "not verifiable, but here's a hypothesis anyway" result a
        # downstream reader could wrongly trust as a real hypothesis.
        if self.status == HypothesisStatus.NOT_VERIFIABLE and self.hypothesis is not None:
            raise ValueError("status=not_verifiable không được kèm theo hypothesis")
        return self
