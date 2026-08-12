from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from shared.models.signal import (
    DastLocation,
    NormalizedSeverity,
    NormalizedSignal,
    RawReference,
    RuleInfo,
    SastLocation,
    ScaLocation,
    SeverityInfo,
    SignalCoverage,
    SignalSource,
    SignalType,
    TargetHint,
)


def _base_kwargs(location):
    return dict(
        signal_id="sig_0f3a1c2e",
        source=SignalSource(
            tool="semgrep",
            tool_version="1.78.0",
            type=SignalType.SAST,
            coverage=SignalCoverage.COMPLETE,
        ),
        rule=RuleInfo(
            id="python.django.security.audit.sqli",
            name="Potential SQL injection",
            cwe=["CWE-89"],
        ),
        severity=SeverityInfo(raw="ERROR", normalized=NormalizedSeverity.HIGH),
        location=location,
        signal_context="cursor.execute(query % user_input)",
        target_hint=TargetHint(system_hint="nxkeeper", component_hint="auth-service"),
        ingested_at=datetime.now(timezone.utc),
        raw_reference=RawReference(
            storage_path="reports/semgrep_001.json", hash="sha256:abc123"
        ),
    )


def test_normalized_signal_sast_location():
    signal = NormalizedSignal(
        **_base_kwargs(SastLocation(file_path="app/views.py", start_line=42, end_line=42))
    )
    assert isinstance(signal.location, SastLocation)


def test_normalized_signal_sca_location():
    signal = NormalizedSignal(
        **_base_kwargs(
            ScaLocation(
                package_name="requests",
                installed_version="2.25.0",
                fixed_version="2.31.0",
                artifact_ref="requirements.txt",
            )
        )
    )
    assert isinstance(signal.location, ScaLocation)


def test_normalized_signal_dast_location():
    signal = NormalizedSignal(
        **_base_kwargs(
            DastLocation(
                url="https://staging.example.com/api/objects/1",
                http_method="GET",
                parameter="id",
            )
        )
    )
    assert isinstance(signal.location, DastLocation)


def test_normalized_signal_missing_required_field():
    kwargs = _base_kwargs(SastLocation(file_path="app/views.py", start_line=1, end_line=1))
    kwargs.pop("signal_id")
    with pytest.raises(ValidationError):
        NormalizedSignal(**kwargs)


def test_normalized_signal_json_schema_generates():
    schema = NormalizedSignal.model_json_schema()
    assert "properties" in schema
    assert "signal_id" in schema["properties"]


def test_no_field_named_evidence():
    schema = NormalizedSignal.model_json_schema()
    assert "evidence" not in schema["properties"]
    assert "signal_context" in schema["properties"]
