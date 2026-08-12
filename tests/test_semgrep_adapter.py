import hashlib
from pathlib import Path

import pytest

from hypothesis_engine.signal_normalizer.semgrep_adapter import SemgrepAdapter
from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from shared.models.signal import NormalizedSeverity, RawReference, SignalCoverage, SignalType

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_sample_report.json"


def test_semgrep_adapter_maps_fields_correctly():
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE),
        tool="semgrep",
        tool_version="1.78.0",
        coverage=SignalCoverage.COMPLETE,
    )

    assert len(signals) == 2

    sqli = signals[0]
    assert sqli.source.tool == "semgrep"
    assert sqli.source.type == SignalType.SAST
    assert sqli.source.coverage == SignalCoverage.COMPLETE
    assert sqli.rule.id == "python.django.security.audit.sqli"
    assert sqli.rule.cwe == [
        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
    ]
    assert sqli.severity.raw == "ERROR"
    assert sqli.severity.normalized == NormalizedSeverity.HIGH
    assert sqli.location.file_path == "app/views.py"
    assert sqli.location.start_line == 42
    assert sqli.location.end_line == 42
    assert "SELECT * FROM users" in sqli.signal_context

    eval_signal = signals[1]
    assert eval_signal.severity.raw == "WARNING"
    assert eval_signal.severity.normalized == NormalizedSeverity.MEDIUM


def test_semgrep_adapter_raw_reference_matches_file_hash():
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE), tool="semgrep", tool_version="1.78.0"
    )
    expected_hash = "sha256:" + hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert all(s.raw_reference.hash == expected_hash for s in signals)


def test_semgrep_adapter_does_not_invent_target_hint():
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE), tool="semgrep", tool_version="1.78.0"
    )
    assert all(s.target_hint.system_hint is None for s in signals)
    assert all(s.target_hint.component_hint is None for s in signals)


def test_semgrep_adapter_missing_required_field_fails_loud():
    raw = {"results": [{"check_id": "some.rule", "start": {"line": 1}, "end": {"line": 1}}]}
    with pytest.raises(KeyError):
        SemgrepAdapter().parse(
            raw,
            RawReference(storage_path="in-memory", hash="sha256:0"),
            tool_version="1.78.0",
            coverage=SignalCoverage.UNKNOWN,
        )
