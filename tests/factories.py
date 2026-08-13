"""Factory dựng NormalizedSignal mẫu dùng chung giữa nhiều test file.

Không phải pytest fixture (không dùng @pytest.fixture) vì test_hypothesis_engine.py
cần truyền trực tiếp làm callable vào @pytest.mark.parametrize — fixture không
dùng được ở đó.
"""

from shared.models.signal import (
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
