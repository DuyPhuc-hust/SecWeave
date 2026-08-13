from enum import Enum
from typing import Optional

from pydantic import BaseModel, model_validator

from shared.models.signal import SignalCoverage


class HypothesisProvenance(BaseModel):
    source_tool: str
    source_signal_id: str
    coverage: SignalCoverage


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
        return self
