from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from hypothesis_engine.signal_normalizer.base import OnSkipCallback, SignalAdapter
from shared.id_generator import generate_id
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

# ZAP Traditional JSON Report (site[].alerts[]) không có field "risk" thuần —
# nó dùng "riskcode" (số, "0".."3") và "riskdesc" (chuỗi hiển thị, ví dụ
# "High (Medium)" = risk (confidence)). Map theo riskcode vì đây là giá trị
# tất định của ZAP, không phụ thuộc format chuỗi hiển thị.
RISKCODE_MAP = {
    "0": NormalizedSeverity.INFO,
    "1": NormalizedSeverity.LOW,
    "2": NormalizedSeverity.MEDIUM,
    "3": NormalizedSeverity.HIGH,
}


class ZapAdapter(SignalAdapter):
    tool_name = "owasp_zap"

    def parse(
        self,
        raw_report: Dict[str, Any],
        raw_reference: RawReference,
        tool_version: str,
        coverage: SignalCoverage,
        on_skip: Optional[OnSkipCallback] = None,
    ) -> List[NormalizedSignal]:
        signals = []
        for site in raw_report.get("site", []):
            for alert_index, alert in enumerate(site.get("alerts", [])):
                raw_severity = alert.get("riskdesc") or "Unknown"
                riskcode = str(alert.get("riskcode") or "")
                cweid = alert.get("cweid")
                cwe = [f"CWE-{cweid}"] if cweid and str(cweid) not in ("-1", "0") else []

                instances = alert.get("instances", [])
                if not instances and on_skip:
                    plugin_id = alert.get("pluginid", "?")
                    on_skip(
                        f"Bỏ qua alert pluginid={plugin_id} (owasp_zap): "
                        f"không có instance nào (instances rỗng)"
                    )

                for instance_index, instance in enumerate(instances):
                    try:
                        signals.append(
                            NormalizedSignal(
                                signal_id=generate_id("sig"),
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
                                    normalized=RISKCODE_MAP.get(riskcode, NormalizedSeverity.INFO),
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
                    except (KeyError, ValidationError, TypeError) as exc:
                        if on_skip:
                            on_skip(
                                f"Bỏ qua alert[{alert_index}].instances[{instance_index}] "
                                f"(owasp_zap): thiếu/sai field — {exc}"
                            )
        return signals
