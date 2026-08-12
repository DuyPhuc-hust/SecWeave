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
    assert signal.severity.raw == "Medium"
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


def test_zap_adapter_missing_uri_fails_loud():
    raw = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "10202",
                        "risk": "Low",
                        "instances": [{"method": "GET"}],
                    }
                ]
            }
        ]
    }
    with pytest.raises(KeyError):
        ZapAdapter().parse(
            raw_report=raw,
            raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
            tool_version="2.14.0",
            coverage=SignalCoverage.UNKNOWN,
        )
