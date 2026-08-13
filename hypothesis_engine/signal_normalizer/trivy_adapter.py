from datetime import datetime, timezone
from typing import Any, Dict, List

from hypothesis_engine.signal_normalizer.base import SignalAdapter
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
    ) -> List[NormalizedSignal]:
        signal_type = (
            SignalType.CONTAINER
            if raw_report.get("ArtifactType") == "container_image"
            else SignalType.SCA
        )

        signals = []
        for result in raw_report.get("Results", []):
            artifact_ref = result["Target"]
            for vuln in result.get("Vulnerabilities", []):
                raw_severity = vuln.get("Severity", "UNKNOWN")
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
                            cwe=vuln.get("CweIDs", []),
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
        return signals
