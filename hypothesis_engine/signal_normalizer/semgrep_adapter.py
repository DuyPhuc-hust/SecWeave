from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from hypothesis_engine.signal_normalizer.base import OnSkipCallback, SignalAdapter, container_as_list
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
    # Semgrep Pro/Supply Chain can emit CRITICAL for reachability analysis —
    # without this mapping, the unrecognized value would fall through to the
    # default INFO, silently downgrading a serious finding to the lowest
    # severity.
    "CRITICAL": NormalizedSeverity.CRITICAL,
}


def _as_cwe_list(value: Any) -> List[str]:
    # metadata.cwe is usually a list, but some Semgrep rule authors emit a
    # bare string instead of a single-element list — normalize both shapes
    # instead of letting pydantic raise a ValidationError (List[str] doesn't
    # auto-accept a bare string).
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
        for index, result in enumerate(container_as_list(raw_report, "results", "results", on_skip)):
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
                # AttributeError: entry in "results" is not an object (e.g. a
                # string/list/null slipping in from a corrupted report or a
                # mismatched --tool).
                if on_skip:
                    on_skip(f"Bỏ qua results[{index}] (semgrep): thiếu/sai field — {exc}")
        return signals
