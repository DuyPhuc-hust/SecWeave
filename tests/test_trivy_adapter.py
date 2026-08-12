from pathlib import Path

import pytest

from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from hypothesis_engine.signal_normalizer.trivy_adapter import TrivyAdapter
from shared.models.signal import NormalizedSeverity, RawReference, SignalCoverage, SignalType

FIXTURE = Path(__file__).parent / "fixtures" / "trivy_sample_report.json"


def test_trivy_adapter_maps_fields_correctly():
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE),
        tool="trivy",
        tool_version="0.53.0",
        coverage=SignalCoverage.COMPLETE,
    )

    assert len(signals) == 1
    signal = signals[0]

    assert signal.source.tool == "trivy"
    assert signal.source.type == SignalType.SCA
    assert signal.rule.id == "CVE-2023-32681"
    assert signal.rule.cwe == ["CWE-200"]
    assert signal.severity.raw == "HIGH"
    assert signal.severity.normalized == NormalizedSeverity.HIGH
    assert signal.location.package_name == "requests"
    assert signal.location.installed_version == "2.25.0"
    assert signal.location.fixed_version == "2.31.0"
    assert signal.location.artifact_ref == "requirements.txt"
    assert "Proxy-Authorization header leak" in signal.signal_context


def test_trivy_adapter_container_artifact_type():
    raw = {
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "myapp:latest (alpine 3.18.4)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-0001",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.8-r0",
                        "Severity": "CRITICAL",
                    }
                ],
            }
        ],
    }
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.53.0",
        coverage=SignalCoverage.COMPLETE,
    )
    assert signals[0].source.type == SignalType.CONTAINER
    assert signals[0].severity.normalized == NormalizedSeverity.CRITICAL


def test_trivy_adapter_result_with_no_vulnerabilities_key_produces_no_signals():
    # Trivy thường trả về một Result entry cho mỗi package type đã quét, kể cả
    # khi không tìm thấy lỗ hổng nào — khi đó key "Vulnerabilities" có thể vắng mặt.
    raw = {
        "ArtifactType": "filesystem",
        "Results": [{"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip"}],
    }
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.53.0",
        coverage=SignalCoverage.COMPLETE,
    )
    assert signals == []


def test_trivy_adapter_missing_target_fails_loud():
    raw = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-0001",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.8-r0",
                        "Severity": "CRITICAL",
                    }
                ]
            }
        ]
    }
    with pytest.raises(KeyError):
        TrivyAdapter().parse(
            raw_report=raw,
            raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
            tool_version="0.53.0",
            coverage=SignalCoverage.COMPLETE,
        )
