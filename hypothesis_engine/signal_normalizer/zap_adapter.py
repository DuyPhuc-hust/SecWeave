import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from hypothesis_engine.signal_normalizer.base import SignalAdapter
from shared.models.signal import (
    DastLocation,
    NormalizedSeverity,
    NormalizedSignal,
    RawReference,
    RuleInfo,
    SeverityInfo,
    SignalCoverage,
    SignalSource,
    SignalType,
    TargetHint,
)

SEVERITY_MAP = {
    "High": NormalizedSeverity.HIGH,
    "Medium": NormalizedSeverity.MEDIUM,
    "Low": NormalizedSeverity.LOW,
    "Informational": NormalizedSeverity.INFO,
}


class ZapAdapter(SignalAdapter):
    tool_name = "owasp_zap"

    def parse(
        self,
        raw_report: Dict[str, Any],
        raw_reference: RawReference,
        tool_version: str,
        coverage: SignalCoverage,
    ) -> List[NormalizedSignal]:
        signals = []
        for site in raw_report.get("site", []):
            for alert in site.get("alerts", []):
                raw_severity = alert.get("risk", "Informational")
                cweid = alert.get("cweid")
                cwe = [f"CWE-{cweid}"] if cweid and str(cweid) not in ("-1", "0") else []

                for instance in alert.get("instances", []):
                    signals.append(
                        NormalizedSignal(
                            signal_id=f"sig_{uuid.uuid4().hex[:12]}",
                            source=SignalSource(
                                tool=self.tool_name,
                                tool_version=tool_version,
                                type=SignalType.DAST,
                                coverage=coverage,
                            ),
                            rule=RuleInfo(
                                id=str(alert["pluginid"]),
                                name=alert.get("alert", str(alert["pluginid"])),
                                cwe=cwe,
                            ),
                            severity=SeverityInfo(
                                raw=raw_severity,
                                normalized=SEVERITY_MAP.get(raw_severity, NormalizedSeverity.INFO),
                            ),
                            location=DastLocation(
                                url=instance["uri"],
                                http_method=instance["method"],
                                parameter=instance.get("param") or None,
                            ),
                            signal_context=instance.get("evidence") or alert.get("desc", ""),
                            target_hint=TargetHint(),
                            ingested_at=datetime.now(timezone.utc),
                            raw_reference=raw_reference,
                        )
                    )
        return signals
