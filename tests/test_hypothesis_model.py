import pytest
from pydantic import ValidationError

from shared.models.hypothesis import (
    Hypothesis,
    HypothesisProvenance,
    HypothesisResult,
    HypothesisStatus,
)
from shared.models.signal import SastLocation, SignalCoverage


def _hypothesis():
    return Hypothesis(
        hypothesis_id="hyp_test1",
        expected_behavior="Chỉ owner của object mới đọc được object đó.",
        suspected_behavior="Object có thể đọc được bởi identity không sở hữu nó.",
        observation_criteria="Response trả về dữ liệu object khi identity khác owner gọi endpoint.",
        provenance=HypothesisProvenance(
            source_tool="semgrep",
            source_signal_id="sig_1",
            coverage=SignalCoverage.COMPLETE,
            location=SastLocation(file_path="app/views.py", start_line=1, end_line=1),
        ),
    )


def test_hypothesis_result_valid_hypothesis():
    result = HypothesisResult(status=HypothesisStatus.HYPOTHESIS, hypothesis=_hypothesis())
    assert result.hypothesis.expected_behavior.startswith("Chỉ owner")
    assert result.hypothesis.hypothesis_id == "hyp_test1"


def test_hypothesis_requires_hypothesis_id():
    with pytest.raises(ValidationError):
        Hypothesis(
            expected_behavior="a",
            suspected_behavior="b",
            observation_criteria="c",
            provenance=HypothesisProvenance(
                source_tool="semgrep",
                source_signal_id="sig_1",
                coverage=SignalCoverage.COMPLETE,
                location=SastLocation(file_path="app/views.py", start_line=1, end_line=1),
            ),
        )


def test_hypothesis_result_not_verifiable_requires_reason():
    with pytest.raises(ValidationError):
        HypothesisResult(status=HypothesisStatus.NOT_VERIFIABLE)


def test_hypothesis_result_hypothesis_status_requires_hypothesis():
    with pytest.raises(ValidationError):
        HypothesisResult(status=HypothesisStatus.HYPOTHESIS)


def test_hypothesis_result_not_verifiable_forbids_a_hypothesis():
    # Real gap found via independent review: the same one-directional
    # validator bug already fixed in ActionPlanResult/PlanCheckResult/
    # CostDecision/PlanReviewResult — this sibling model was missing its
    # own converse check, so status=not_verifiable + a real hypothesis
    # attached used to construct without error.
    with pytest.raises(ValidationError):
        HypothesisResult(status=HypothesisStatus.NOT_VERIFIABLE, hypothesis=_hypothesis(), reason="x")


def test_hypothesis_result_not_verifiable_valid():
    result = HypothesisResult(
        status=HypothesisStatus.NOT_VERIFIABLE,
        reason="Tín hiệu severity info, không có đủ ngữ cảnh để phân biệt hành vi đúng/sai.",
    )
    assert result.hypothesis is None
