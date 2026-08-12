import json

import pytest

from hypothesis_engine.engine import HypothesisEngine
from hypothesis_engine.llm_client.fake_client import FakeLLMClient
from shared.models.hypothesis import HypothesisStatus
from shared.models.signal import (
    NormalizedSignal,
    RawReference,
    RuleInfo,
    SastLocation,
    SeverityInfo,
    SignalCoverage,
    SignalSource,
    SignalType,
    TargetHint,
)


def _signal():
    return NormalizedSignal(
        signal_id="sig_test1",
        source=SignalSource(
            tool="semgrep", tool_version="1.78.0", type=SignalType.SAST, coverage=SignalCoverage.COMPLETE
        ),
        rule=RuleInfo(id="python.django.security.audit.sqli", name="Potential SQL injection", cwe=["CWE-89"]),
        severity=SeverityInfo(raw="ERROR", normalized="high"),
        location=SastLocation(file_path="app/views.py", start_line=42, end_line=42),
        signal_context="cursor.execute(query % user_id)",
        target_hint=TargetHint(),
        ingested_at="2026-08-12T00:00:00Z",
        raw_reference=RawReference(storage_path="x", hash="sha256:0"),
    )


def test_engine_produces_hypothesis_from_valid_llm_response():
    valid_response = json.dumps(
        {
            "verifiable": True,
            "expected_behavior": "Query phải dùng parameterized statement.",
            "suspected_behavior": "Query nối chuỗi trực tiếp với input người dùng.",
            "observation_criteria": "So sánh request chứa ký tự đặc biệt SQL với response/log lỗi DB.",
        }
    )
    engine = HypothesisEngine(FakeLLMClient(responses=[valid_response]))
    result = engine.generate_hypothesis(_signal())

    assert result.status == HypothesisStatus.HYPOTHESIS
    assert result.hypothesis.provenance.source_tool == "semgrep"
    assert result.hypothesis.provenance.source_signal_id == "sig_test1"
    assert result.hypothesis.provenance.coverage == SignalCoverage.COMPLETE


def test_engine_returns_not_verifiable_when_llm_says_so():
    response = json.dumps({"verifiable": False, "reason": "Signal quá mơ hồ, không tách được hành vi đúng/sai."})
    engine = HypothesisEngine(FakeLLMClient(responses=[response]))
    result = engine.generate_hypothesis(_signal())

    assert result.status == HypothesisStatus.NOT_VERIFIABLE
    assert "mơ hồ" in result.reason


def test_engine_returns_not_verifiable_on_missing_required_field():
    response = json.dumps({"verifiable": True, "expected_behavior": "X"})  # thiếu 2 field
    engine = HypothesisEngine(FakeLLMClient(responses=[response]))
    result = engine.generate_hypothesis(_signal())

    assert result.status == HypothesisStatus.NOT_VERIFIABLE
    assert "suspected_behavior" in result.reason
    assert "observation_criteria" in result.reason


def test_engine_does_not_fabricate_on_invalid_json():
    engine = HypothesisEngine(FakeLLMClient(responses=["đây không phải JSON"]))
    result = engine.generate_hypothesis(_signal())

    assert result.status == HypothesisStatus.NOT_VERIFIABLE
    assert result.hypothesis is None


def test_engine_returns_not_verifiable_when_llm_returns_json_array_not_object():
    engine = HypothesisEngine(FakeLLMClient(responses=["[1, 2, 3]"]))
    result = engine.generate_hypothesis(_signal())

    assert result.status == HypothesisStatus.NOT_VERIFIABLE


def test_engine_extracts_json_wrapped_in_markdown_fence():
    # LLM thật hay trả JSON kèm ```json ... ``` dù prompt đã yêu cầu JSON thuần.
    fenced_response = (
        "```json\n"
        + json.dumps(
            {
                "verifiable": True,
                "expected_behavior": "a",
                "suspected_behavior": "b",
                "observation_criteria": "c",
            }
        )
        + "\n```"
    )
    engine = HypothesisEngine(FakeLLMClient(responses=[fenced_response]))
    result = engine.generate_hypothesis(_signal())

    assert result.status == HypothesisStatus.HYPOTHESIS
    assert result.hypothesis.expected_behavior == "a"


def test_engine_propagates_llm_call_failures_instead_of_swallowing_them():
    # Lỗi hạ tầng (mất mạng, hết quota...) khác bản chất với "signal không đủ để
    # lập giả thuyết" — không được để hai loại lỗi này lẫn vào nhau thành cùng
    # một NOT_VERIFIABLE, vì sẽ che mất sự cố vận hành thật.
    def _raise(_prompt: str) -> str:
        raise ConnectionError("LLM provider unreachable")

    engine = HypothesisEngine(FakeLLMClient(response_fn=_raise))
    with pytest.raises(ConnectionError):
        engine.generate_hypothesis(_signal())


def test_engine_prompt_never_contains_blind_marker_concept():
    # Ràng buộc cứng SPEC §4.1: Hypothesis Engine không được biết blind marker.
    # Test này khoá lại việc build_prompt không vô tình đưa khái niệm đó vào.
    fake = FakeLLMClient(
        responses=[
            json.dumps(
                {
                    "verifiable": True,
                    "expected_behavior": "a",
                    "suspected_behavior": "b",
                    "observation_criteria": "c",
                }
            )
        ]
    )
    engine = HypothesisEngine(fake)
    engine.generate_hypothesis(_signal())
    assert "blind marker" not in fake.calls[0].lower()
    assert "marker" not in fake.calls[0].lower()
