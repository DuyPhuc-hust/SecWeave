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
        for result_index, result in enumerate(container_as_list(raw_report, "Results", "Results", on_skip)):
            try:
                artifact_ref = result["Target"]
            except (KeyError, TypeError) as exc:
                # TypeError: result is not an object (e.g. a string/list/null
                # slipping into "Results" from a corrupted report or a
                # mismatched --tool).
                if on_skip:
                    on_skip(f"Bỏ qua Results[{result_index}] (trivy): thiếu/sai field — {exc}")
                continue

            vulnerabilities = container_as_list(
                result, "Vulnerabilities", f"Results[{result_index}].Vulnerabilities", on_skip
            )
            for vuln_index, vuln in enumerate(vulnerabilities):
                try:
                    # "Severity" can be either absent OR present but null —
                    # both cases must fall back to "UNKNOWN" (the value Trivy
                    # actually uses); .get(key, default) only catches absence.
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

            # Trivy's secret-detection results (Class=="secret") live in a
            # completely separate "Secrets" key with its own shape (RuleID/
            # Category/Title/StartLine/EndLine/Match, not VulnerabilityID/
            # PkgName/...) — found via real Trivy output that this adapter
            # was silently dropping actual secrets (including a real RSA
            # private key in a scanned image) with no on_skip warning at all,
            # since it only ever read "Vulnerabilities". Location reuses
            # SastLocation: a secret is a file+line finding, same shape as a
            # SAST result, not a package-version finding like ScaLocation.
            secrets = container_as_list(result, "Secrets", f"Results[{result_index}].Secrets", on_skip)
            for secret_index, secret in enumerate(secrets):
                try:
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
                                id=secret["RuleID"],
                                name=secret.get("Title", secret["RuleID"]),
                                cwe=[],
                            ),
                            severity=SeverityInfo(
                                raw=secret.get("Severity") or "UNKNOWN",
                                normalized=SEVERITY_MAP.get(secret.get("Severity") or "UNKNOWN", NormalizedSeverity.INFO),
                            ),
                            location=SastLocation(
                                file_path=artifact_ref,
                                start_line=secret["StartLine"],
                                end_line=secret["EndLine"],
                            ),
                            signal_context=f"{secret.get('Title', '')}\n\n{secret.get('Match', '')}".strip(),
                            target_hint=TargetHint(),
                            ingested_at=datetime.now(timezone.utc),
                            raw_reference=raw_reference,
                        )
                    )
                except (KeyError, ValidationError, TypeError, AttributeError) as exc:
                    if on_skip:
                        on_skip(
                            f"Bỏ qua Results[{result_index}].Secrets[{secret_index}] "
                            f"(trivy): thiếu/sai field — {exc}"
                        )
        return signals
