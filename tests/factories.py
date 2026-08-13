"""Factory dựng NormalizedSignal mẫu dùng chung giữa nhiều test file.

Không phải pytest fixture (không dùng @pytest.fixture) vì test_hypothesis_engine.py
cần truyền trực tiếp làm callable vào @pytest.mark.parametrize — fixture không
dùng được ở đó.
"""

from datetime import datetime, timezone

from shared.models.entities import Authorization, AuthorizationLayer
from shared.models.hypothesis import Hypothesis, HypothesisProvenance
from shared.models.signal import (
    DastLocation,
    NormalizedSignal,
    RawReference,
    RuleInfo,
    SeverityInfo,
    SastLocation,
    SignalCoverage,
    SignalSource,
    SignalType,
    TargetHint,
)


def semgrep_sqli_signal() -> NormalizedSignal:
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


def sample_hypothesis() -> Hypothesis:
    return Hypothesis(
        hypothesis_id="hyp_test1",
        expected_behavior="The API only returns objects owned by the requesting identity.",
        suspected_behavior="The API returns objects regardless of ownership when the id is guessed.",
        observation_criteria="Compare the response for the owner identity vs a non-owner identity "
        "calling GET /api/objects/{id} with the same id.",
        provenance=HypothesisProvenance(
            source_tool="owasp_zap",
            source_signal_id="sig_test1",
            coverage=SignalCoverage.COMPLETE,
            location=DastLocation(url="https://staging.example.com/api/objects/{id}", http_method="GET"),
        ),
    )


def sample_authorization(**overrides) -> Authorization:
    defaults = dict(
        id="auth_test1",
        layer=AuthorizationLayer.TARGET_AUTHORIZATION,
        approved_by="owner",
        approved_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        target_id="tgt_1",
        identity="test-identity-1",
        allowed_actions=["GET https://staging.example.com/api/objects/{id}"],
    )
    defaults.update(overrides)
    return Authorization(**defaults)
