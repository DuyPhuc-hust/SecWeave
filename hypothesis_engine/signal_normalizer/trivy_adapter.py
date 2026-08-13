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
    ScaLocation,
    SeverityInfo,
    SignalCoverage,
    SignalSource,
    SignalType,
    TargetHint,
)

SEVERITY_MAP = {
    "CRITICAL": NormalizedSeverity.CRITICAL,
    "HIGH": NormalizedSeverity.HIGH,
    "MEDIUM": NormalizedSeverity.MEDIUM,
    "LOW": NormalizedSeverity.LOW,
    "UNKNOWN": NormalizedSeverity.INFO,
}


class TrivyAdapter(SignalAdapter):
    tool_name = "trivy"

    def parse(
        self,
        raw_report: Dict[str, Any],
        raw_reference: RawReference,
        tool_version: str,
        coverage: SignalCoverage,
        on_skip: Optional[OnSkipCallback] = None,
    ) -> List[NormalizedSignal]:
        signal_type = (
            SignalType.CONTAINER
            if raw_report.get("ArtifactType") == "container_image"
            else SignalType.SCA
        )

        signals = []
        for result_index, result in enumerate(raw_report.get("Results", [])):
            try:
                artifact_ref = result["Target"]
            except (KeyError, TypeError) as exc:
                # TypeError: result không phải object (ví dụ string/list/null
                # lọt vào "Results" do report bị hỏng hoặc gán nhầm --tool).
                if on_skip:
                    on_skip(f"Bỏ qua Results[{result_index}] (trivy): thiếu/sai field — {exc}")
                continue

            for vuln_index, vuln in enumerate(result.get("Vulnerabilities", [])):
                try:
                    # "Severity" có thể vắng mặt HOẶC có mặt nhưng là null — cả
                    # 2 trường hợp đều phải rơi về "UNKNOWN" (giá trị Trivy
                    # thật sự dùng), .get(key, default) chỉ bắt được vắng mặt.
                    raw_severity = vuln.get("Severity") or "UNKNOWN"
                    title = vuln.get("Title", "")
                    description = vuln.get("Description", "")

                    signals.append(
                        NormalizedSignal(
                            signal_id=generate_id("sig"),
                            source=SignalSource(
                                tool=self.tool_name,
                                tool_version=tool_version,
                                type=signal_type,
                                coverage=coverage,
                            ),
                            rule=RuleInfo(
                                id=vuln["VulnerabilityID"],
                                name=title or vuln["VulnerabilityID"],
                                cwe=vuln.get("CweIDs") or [],
                            ),
                            severity=SeverityInfo(
                                raw=raw_severity,
                                normalized=SEVERITY_MAP.get(raw_severity, NormalizedSeverity.INFO),
                            ),
                            location=ScaLocation(
                                package_name=vuln["PkgName"],
                                installed_version=vuln["InstalledVersion"],
                                fixed_version=vuln.get("FixedVersion"),
                                artifact_ref=artifact_ref,
                            ),
                            signal_context=f"{title}\n\n{description}".strip(),
                            target_hint=TargetHint(),
                            ingested_at=datetime.now(timezone.utc),
                            raw_reference=raw_reference,
                        )
                    )
                except (KeyError, ValidationError, TypeError, AttributeError) as exc:
                    if on_skip:
                        on_skip(
                            f"Bỏ qua Results[{result_index}].Vulnerabilities[{vuln_index}] "
                            f"(trivy): thiếu/sai field — {exc}"
                        )
        return signals
