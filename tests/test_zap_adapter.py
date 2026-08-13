from pathlib import Path

import pytest

from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from hypothesis_engine.signal_normalizer.zap_adapter import ZapAdapter
from shared.models.signal import NormalizedSeverity, RawReference, SignalCoverage, SignalType

FIXTURE = Path(__file__).parent / "fixtures" / "zap_sample_report.json"


def test_zap_adapter_maps_fields_correctly():
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE),
        tool="owasp_zap",
        tool_version="2.14.0",
        coverage=SignalCoverage.PARTIAL,
    )

    assert len(signals) == 1
    signal = signals[0]

    assert signal.source.tool == "owasp_zap"
    assert signal.source.type == SignalType.DAST
    assert signal.source.coverage == SignalCoverage.PARTIAL
    assert signal.rule.id == "10202"
    assert signal.rule.cwe == ["CWE-352"]
    assert signal.severity.raw == "Medium (Medium)"
    assert signal.severity.normalized == NormalizedSeverity.MEDIUM
    assert signal.location.url == "https://staging.example.com/api/objects/1"
    assert signal.location.http_method == "GET"
    assert signal.location.parameter is None
    assert signal.signal_context == '<form method="POST">'


def test_zap_adapter_evidence_field_is_never_named_evidence_in_output():
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE), tool="owasp_zap", tool_version="2.14.0"
    )
    schema = type(signals[0]).model_json_schema()
    assert "evidence" not in schema["properties"]


@pytest.mark.parametrize(
    "riskcode,expected",
    [
        ("0", NormalizedSeverity.INFO),
        ("1", NormalizedSeverity.LOW),
        ("2", NormalizedSeverity.MEDIUM),
        ("3", NormalizedSeverity.HIGH),
    ],
)
def test_zap_adapter_maps_riskcode_to_severity(riskcode, expected):
    from hypothesis_engine.signal_normalizer.zap_adapter import ZapAdapter

    raw = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "1",
                        "riskcode": riskcode,
                        "riskdesc": "irrelevant (Medium)",
                        "instances": [{"uri": "https://x/", "method": "GET"}],
                    }
                ]
            }
        ]
    }
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.UNKNOWN,
    )
    assert signals[0].severity.normalized == expected


def test_zap_adapter_ignores_legacy_risk_field_not_used_by_real_zap():
    # Regression: ZAP thật không có field "risk" thuần (chỉ có riskcode/riskdesc,
    # xem SPEC §4.1.1 — bảng ánh xạ của SPEC ghi "risk" nhưng đó là nhầm lẫn với
    # ZAP REST API /core/view/alerts, khác cấu trúc site[].alerts[].instances[]
    # mà adapter này dùng). Nếu ai đó vô tình thêm lại field "risk" giả, test này
    # phải khẳng định nó KHÔNG được dùng để suy ra severity.
    from hypothesis_engine.signal_normalizer.zap_adapter import ZapAdapter

    raw = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "1",
                        "risk": "High",  # field giả, không có thật trong ZAP
                        "riskcode": "0",
                        "riskdesc": "Informational (Medium)",
                        "instances": [{"uri": "https://x/", "method": "GET"}],
                    }
                ]
            }
        ]
    }
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.UNKNOWN,
    )
    assert signals[0].severity.normalized == NormalizedSeverity.INFO
    assert signals[0].severity.raw == "Informational (Medium)"


def test_zap_adapter_skips_instance_missing_uri_and_reports_it_via_on_skip():
    # instances[0] thiếu "uri", instances[1] hợp lệ — chỉ bỏ qua instance lỗi.
    raw = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "10202",
                        "riskcode": "1",
                        "riskdesc": "Low (Medium)",
                        "instances": [
                            {"method": "GET"},
                            {"uri": "https://x/ok", "method": "GET"},
                        ],
                    }
                ]
            }
        ]
    }
    skipped = []
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.UNKNOWN,
        on_skip=skipped.append,
    )

    assert len(signals) == 1
    assert signals[0].location.url == "https://x/ok"
    assert len(skipped) == 1
    assert "instances[0]" in skipped[0]
    assert "owasp_zap" in skipped[0]


def test_zap_adapter_alert_with_no_instances_reports_via_on_skip():
    raw = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "99",
                        "riskcode": "0",
                        "riskdesc": "Informational (Low)",
                        "instances": [],
                    }
                ]
            }
        ]
    }
    skipped = []
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.UNKNOWN,
        on_skip=skipped.append,
    )

    assert signals == []
    assert len(skipped) == 1
    assert "pluginid=99" in skipped[0]
    assert "không có instance nào" in skipped[0]
