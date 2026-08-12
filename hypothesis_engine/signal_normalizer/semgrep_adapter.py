import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from hypothesis_engine.signal_normalizer.base import SignalAdapter
from shared.models.signal import (
    NormalizedSeverity,
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

SEVERITY_MAP = {
    "ERROR": NormalizedSeverity.HIGH,
    "WARNING": NormalizedSeverity.MEDIUM,
    "INFO": NormalizedSeverity.INFO,
}


class SemgrepAdapter(SignalAdapter):
    tool_name = "semgrep"

    def parse(
        self,
        raw_report: Dict[str, Any],
        raw_reference: RawReference,
        tool_version: str,
        coverage: SignalCoverage,
    ) -> List[NormalizedSignal]:
        signals = []
        for result in raw_report.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            raw_severity = extra.get("severity", "INFO")

            signals.append(
                NormalizedSignal(
                    signal_id=f"sig_{uuid.uuid4().hex[:12]}",
                    source=SignalSource(
                        tool=self.tool_name,
                        tool_version=tool_version,
                        type=SignalType.SAST,
                        coverage=coverage,
                    ),
                    rule=RuleInfo(
                        id=result["check_id"],
                        name=extra.get("message", result["check_id"]),
                        cwe=metadata.get("cwe", []),
                    ),
                    severity=SeverityInfo(
                        raw=raw_severity,
                        normalized=SEVERITY_MAP.get(raw_severity, NormalizedSeverity.INFO),
                    ),
                    location=SastLocation(
                        file_path=result["path"],
                        start_line=result["start"]["line"],
                        end_line=result["end"]["line"],
                    ),
                    signal_context=extra.get("lines", ""),
                    target_hint=TargetHint(),
                    ingested_at=datetime.now(timezone.utc),
                    raw_reference=raw_reference,
                )
            )
        return signals
