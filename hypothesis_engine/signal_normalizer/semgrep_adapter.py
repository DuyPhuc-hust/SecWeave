from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from hypothesis_engine.signal_normalizer.base import OnSkipCallback, SignalAdapter
from shared.id_generator import generate_id
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
    # Semgrep Pro/Supply Chain có thể phát ra CRITICAL cho reachability
    # analysis — nếu không map, giá trị lạ sẽ rơi vào default INFO, tức hạ
    # 1 finding nghiêm trọng xuống mức thấp nhất một cách âm thầm.
    "CRITICAL": NormalizedSeverity.CRITICAL,
}


def _as_cwe_list(value: Any) -> List[str]:
    # metadata.cwe thường là list, nhưng một số rule author của Semgrep phát ra
    # bare string thay vì list 1 phần tử — chuẩn hoá cho cả 2 dạng thay vì để
    # pydantic ném ValidationError (List[str] không tự nhận string trần).
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


class SemgrepAdapter(SignalAdapter):
    tool_name = "semgrep"

    def parse(
        self,
        raw_report: Dict[str, Any],
        raw_reference: RawReference,
        tool_version: str,
        coverage: SignalCoverage,
        on_skip: Optional[OnSkipCallback] = None,
    ) -> List[NormalizedSignal]:
        signals = []
        for index, result in enumerate(raw_report.get("results", [])):
            try:
                extra = result.get("extra", {})
                metadata = extra.get("metadata", {})
                raw_severity = extra.get("severity") or "INFO"

                signals.append(
                    NormalizedSignal(
                        signal_id=generate_id("sig"),
                        source=SignalSource(
                            tool=self.tool_name,
                            tool_version=tool_version,
                            type=SignalType.SAST,
                            coverage=coverage,
                        ),
                        rule=RuleInfo(
                            id=result["check_id"],
                            name=extra.get("message", result["check_id"]),
                            cwe=_as_cwe_list(metadata.get("cwe")),
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
            except (KeyError, ValidationError, TypeError, AttributeError) as exc:
                # AttributeError: entry trong "results" không phải object (ví dụ
                # string/list/null lọt vào do report bị hỏng hoặc gán nhầm --tool).
                if on_skip:
                    on_skip(f"Bỏ qua results[{index}] (semgrep): thiếu/sai field — {exc}")
        return signals
