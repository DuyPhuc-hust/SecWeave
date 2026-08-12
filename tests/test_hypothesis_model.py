import pytest
from pydantic import ValidationError

from shared.models.hypothesis import (
    Hypothesis,
    HypothesisProvenance,
    HypothesisResult,
    HypothesisStatus,
)
from shared.models.signal import SignalCoverage


def _hypothesis():
    return Hypothesis(
        expected_behavior="Chỉ owner của object mới đọc được object đó.",
        suspected_behavior="Object có thể đọc được bởi identity không sở hữu nó.",
        observation_criteria="Response trả về dữ liệu object khi identity khác owner gọi endpoint.",
        provenance=HypothesisProvenance(
            source_tool="semgrep", source_signal_id="sig_1", coverage=SignalCoverage.COMPLETE
        ),
    )


def test_hypothesis_result_valid_hypothesis():
    result = HypothesisResult(status=HypothesisStatus.HYPOTHESIS, hypothesis=_hypothesis())
    assert result.hypothesis.expected_behavior.startswith("Chỉ owner")


def test_hypothesis_result_not_verifiable_requires_reason():
    with pytest.raises(ValidationError):
        HypothesisResult(status=HypothesisStatus.NOT_VERIFIABLE)


def test_hypothesis_result_hypothesis_status_requires_hypothesis():
    with pytest.raises(ValidationError):
        HypothesisResult(status=HypothesisStatus.HYPOTHESIS)


def test_hypothesis_result_not_verifiable_valid():
    result = HypothesisResult(
        status=HypothesisStatus.NOT_VERIFIABLE,
        reason="Tín hiệu severity info, không có đủ ngữ cảnh để phân biệt hành vi đúng/sai.",
    )
    assert result.hypothesis is None
