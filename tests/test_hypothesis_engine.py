import json

import pytest

from hypothesis_engine.engine import HypothesisEngine
from hypothesis_engine.llm_client.fake_client import FakeLLMClient
from shared.models.hypothesis import HypothesisStatus
from shared.models.signal import (
    DastLocation,
    NormalizedSignal,
    RawReference,
    RuleInfo,
    ScaLocation,
    SeverityInfo,
    SignalCoverage,
    SignalSource,
    SignalType,
    TargetHint,
)
from tests.factories import semgrep_sqli_signal

_semgrep_signal = semgrep_sqli_signal

# Alias giữ để không phải sửa lại toàn bộ test cũ vốn không quan tâm loại signal.
_signal = _semgrep_signal


def _trivy_signal():
    return NormalizedSignal(
        signal_id="sig_test_trivy",
        source=SignalSource(
            tool="trivy", tool_version="0.53.0", type=SignalType.SCA, coverage=SignalCoverage.COMPLETE
        ),
        rule=RuleInfo(id="CVE-2023-32681", name="requests: Proxy-Authorization header leak", cwe=["CWE-200"]),
        severity=SeverityInfo(raw="HIGH", normalized="high"),
        location=ScaLocation(
            package_name="requests",
            installed_version="2.25.0",
            fixed_version="2.31.0",
            artifact_ref="requirements.txt",
        ),
        signal_context="Proxy-Authorization header leak on cross-origin redirect",
        target_hint=TargetHint(),
        ingested_at="2026-08-12T00:00:00Z",
        raw_reference=RawReference(storage_path="x", hash="sha256:0"),
    )


def _zap_signal():
    return NormalizedSignal(
        signal_id="sig_test_zap",
        source=SignalSource(
            tool="owasp_zap", tool_version="2.14.0", type=SignalType.DAST, coverage=SignalCoverage.PARTIAL
        ),
        rule=RuleInfo(id="10202", name="Absence of Anti-CSRF Tokens", cwe=["CWE-352"]),
        severity=SeverityInfo(raw="Medium", normalized="medium"),
        location=DastLocation(
            url="https://staging.example.com/api/objects/1", http_method="GET", parameter=None
        ),
        signal_context='<form method="POST">',
        target_hint=TargetHint(),
        ingested_at="2026-08-12T00:00:00Z",
        raw_reference=RawReference(storage_path="x", hash="sha256:0"),
    )


_VALID_LLM_RESPONSE = json.dumps(
    {
        "verifiable": True,
        "expected_behavior": "a",
        "suspected_behavior": "b",
        "observation_criteria": "c",
    }
)


@pytest.mark.parametrize(
    "signal_factory,expected_tool,expected_coverage,location_field_in_prompt",
    [
        (_semgrep_signal, "semgrep", SignalCoverage.COMPLETE, "start_line"),
        (_trivy_signal, "trivy", SignalCoverage.COMPLETE, "package_name"),
        (_zap_signal, "owasp_zap", SignalCoverage.PARTIAL, "http_method"),
    ],
)
def test_engine_works_regardless_of_signal_source_type(
    signal_factory, expected_tool, expected_coverage, location_field_in_prompt
):
    signal = signal_factory()
    fake = FakeLLMClient(responses=[_VALID_LLM_RESPONSE])
    engine = HypothesisEngine(fake)

    result = engine.generate_hypothesis(signal)

    assert result.status == HypothesisStatus.HYPOTHESIS
    assert result.hypothesis.hypothesis_id.startswith("hyp_")
    assert result.hypothesis.provenance.source_tool == expected_tool
    assert result.hypothesis.provenance.source_signal_id == signal.signal_id
    assert result.hypothesis.provenance.coverage == expected_coverage
    # Đảm bảo prompt thực sự mang đúng field đặc trưng của loại location đó
    # tới LLM — không phải mọi loại signal đều tình cờ hoạt động vì trùng field.
    assert location_field_in_prompt in fake.calls[0]


def test_engine_generates_unique_hypothesis_id_per_call():
    fake = FakeLLMClient(responses=[_VALID_LLM_RESPONSE, _VALID_LLM_RESPONSE])
    engine = HypothesisEngine(fake)

    result_1 = engine.generate_hypothesis(_semgrep_signal())
    result_2 = engine.generate_hypothesis(_semgrep_signal())

    assert result_1.hypothesis.hypothesis_id != result_2.hypothesis.hypothesis_id


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


def test_engine_returns_not_verifiable_when_verifiable_key_missing_entirely():
    # Thiếu hẳn "verifiable" khác với "verifiable": true — dù 3 field text vẫn
    # có mặt, không được âm thầm coi là hợp lệ.
    response = json.dumps(
        {"expected_behavior": "a", "suspected_behavior": "b", "observation_criteria": "c"}
    )
    engine = HypothesisEngine(FakeLLMClient(responses=[response]))
    result = engine.generate_hypothesis(_signal())

    assert result.status == HypothesisStatus.NOT_VERIFIABLE
    assert "verifiable" in result.reason


@pytest.mark.parametrize("falsy_value", ["false", "False", "0", "no", "", None])
def test_engine_recognizes_non_bool_falsy_verifiable_representations(falsy_value):
    response = json.dumps({"verifiable": falsy_value, "reason": "lý do thật của LLM"})
    engine = HypothesisEngine(FakeLLMClient(responses=[response]))
    result = engine.generate_hypothesis(_signal())

    assert result.status == HypothesisStatus.NOT_VERIFIABLE
    assert result.reason == "lý do thật của LLM"


@pytest.mark.parametrize("truthy_value", ["true", "True", 1])
def test_engine_recognizes_non_bool_truthy_verifiable_representations(truthy_value):
    response = json.dumps(
        {
            "verifiable": truthy_value,
            "expected_behavior": "a",
            "suspected_behavior": "b",
            "observation_criteria": "c",
        }
    )
    engine = HypothesisEngine(FakeLLMClient(responses=[response]))
    result = engine.generate_hypothesis(_signal())

    assert result.status == HypothesisStatus.HYPOTHESIS


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


def test_engine_prompt_separates_instructions_from_untrusted_data():
    # signal_context (đặc biệt của ZAP) có thể chứa văn bản trích từ response
    # thật của target đang bị quét — không được để lẫn với phần chỉ dẫn mà
    # không có cảnh báo/dấu phân cách, tránh prompt injection từ dữ liệu target.
    engine = HypothesisEngine(FakeLLMClient(responses=["{}"]))
    prompt = engine.build_prompt(_semgrep_signal(), source_snippet=None, verified_context=None)

    marker = "===== DỮ LIỆU ====="
    assert marker in prompt
    instructions, data = prompt.split(marker, 1)
    assert "là dữ liệu để phân tích" in instructions
    assert "Signal:" in data
    # Toàn bộ nội dung signal (dữ liệu) phải nằm SAU dấu phân cách, không lẫn
    # vào phần chỉ dẫn phía trên.
    assert "Signal:" not in instructions
