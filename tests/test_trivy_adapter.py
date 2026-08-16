from pathlib import Path

from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from hypothesis_engine.signal_normalizer.trivy_adapter import TrivyAdapter
from shared.models.signal import NormalizedSeverity, RawReference, SignalCoverage, SignalType

FIXTURE = Path(__file__).parent / "fixtures" / "trivy_sample_report.json"


def test_trivy_adapter_maps_fields_correctly():
    # FIXTURE is a real `trivy image bkimminich/juice-shop` run (see
    # .secweave/manual_test/ for the session that captured it), trimmed down
    # to 1 real OS-package CVE + 1 real secret finding — not hand-written.
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE),
        tool="trivy",
        tool_version="0.58.0",
        coverage=SignalCoverage.COMPLETE,
    )

    assert len(signals) == 2

    vuln = next(s for s in signals if s.rule.id.startswith("CVE-"))
    assert vuln.source.tool == "trivy"
    assert vuln.source.type == SignalType.CONTAINER
    assert vuln.rule.id == "CVE-2026-5435"
    assert vuln.rule.cwe == ["CWE-787"]
    assert vuln.severity.raw == "MEDIUM"
    assert vuln.severity.normalized == NormalizedSeverity.MEDIUM
    assert vuln.location.package_name == "libc6"
    assert vuln.location.installed_version == "2.41-12+deb13u3"
    assert vuln.location.artifact_ref == "bkimminich/juice-shop (debian 13.6)"
    assert "Out-of-bounds write via TSIG record processing" in vuln.signal_context

    secret = next(s for s in signals if s.rule.id == "private-key")
    assert secret.source.type == SignalType.CONTAINER
    assert secret.rule.name == "Asymmetric Private Key"
    assert secret.severity.normalized == NormalizedSeverity.HIGH
    assert secret.location.file_path == "/juice-shop/lib/insecurity.ts"
    assert secret.location.start_line == 21
    assert "BEGIN RSA PRIVATE KEY" in secret.signal_context


def test_trivy_adapter_sca_type_when_artifact_type_is_not_container_image():
    # The Vulnerabilities entry below is real (same `@tootallnate/once`
    # CVE-2026-3449 finding as in the real juice-shop image scan) — only
    # "ArtifactType" is changed from "container_image" to "filesystem" (a
    # real value `trivy fs` reports) to exercise the adapter's SCA-vs-
    # CONTAINER branch, which the real container-image fixture above can't.
    raw = {
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-3449",
                        "PkgName": "@tootallnate/once",
                        "InstalledVersion": "1.1.2",
                        "FixedVersion": "3.0.1, 2.0.1",
                        "Severity": "LOW",
                        "CweIDs": ["CWE-705"],
                        "Title": "@tootallnate/once: Denial of Service due to incorrect control "
                        "flow scoping with AbortSignal",
                    }
                ],
            }
        ],
    }
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.58.0",
        coverage=SignalCoverage.COMPLETE,
    )
    assert signals[0].source.type == SignalType.SCA
    assert signals[0].severity.normalized == NormalizedSeverity.LOW


def test_trivy_adapter_result_with_no_vulnerabilities_key_produces_no_signals():
    # Trivy typically returns one Result entry per package type scanned,
    # even when no vulnerabilities were found — in that case the
    # "Vulnerabilities" key can be absent.
    raw = {
        "ArtifactType": "filesystem",
        "Results": [{"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip"}],
    }
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.53.0",
        coverage=SignalCoverage.COMPLETE,
    )
    assert signals == []


def test_trivy_adapter_skips_result_missing_target_and_reports_it_via_on_skip():
    # Result[0] is missing "Target" (dropping all of its Vulnerabilities),
    # Result[1] is valid — only Result[0] should be skipped, not Result[1] too.
    raw = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-0001",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.8-r0",
                        "Severity": "CRITICAL",
                    }
                ]
            },
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-0002",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "Severity": "HIGH",
                    }
                ],
            },
        ]
    }
    skipped = []
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.53.0",
        coverage=SignalCoverage.COMPLETE,
        on_skip=skipped.append,
    )

    assert [s.rule.id for s in signals] == ["CVE-2023-0002"]
    assert len(skipped) == 1
    assert "Results[0]" in skipped[0]
    assert "trivy" in skipped[0]


def test_trivy_adapter_skips_result_that_is_not_an_object():
    # Results[0] is not an object (a list slipping in from a corrupted
    # report or a mismatched --tool) — result["Target"] raises TypeError, not
    # KeyError, but must still skip exactly that entry instead of crashing
    # the whole report.
    raw = {
        "Results": [
            ["not", "an", "object"],
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-0002",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "Severity": "HIGH",
                    }
                ],
            },
        ]
    }
    skipped = []
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.53.0",
        coverage=SignalCoverage.COMPLETE,
        on_skip=skipped.append,
    )

    assert [s.rule.id for s in signals] == ["CVE-2023-0002"]
    assert len(skipped) == 1
    assert "Results[0]" in skipped[0]


def test_trivy_adapter_skips_vulnerability_that_is_not_an_object():
    raw = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    "not an object",
                    {
                        "VulnerabilityID": "CVE-2023-0002",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "Severity": "HIGH",
                    },
                ],
            }
        ]
    }
    skipped = []
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.53.0",
        coverage=SignalCoverage.COMPLETE,
        on_skip=skipped.append,
    )

    assert [s.rule.id for s in signals] == ["CVE-2023-0002"]
    assert len(skipped) == 1
    assert "Results[0].Vulnerabilities[0]" in skipped[0]


def test_trivy_adapter_skips_secret_missing_required_field_and_reports_it():
    raw = {
        "Results": [
            {
                "Target": "app.py",
                "Secrets": [
                    {"RuleID": "private-key", "Title": "Asymmetric Private Key"},  # missing StartLine/EndLine
                ],
            }
        ]
    }
    skipped = []
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.58.0",
        coverage=SignalCoverage.COMPLETE,
        on_skip=skipped.append,
    )
    assert signals == []
    assert len(skipped) == 1
    assert "Results[0].Secrets[0]" in skipped[0]


def test_trivy_adapter_null_severity_treated_as_unknown():
    raw = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-9999",
                        "PkgName": "somepkg",
                        "InstalledVersion": "1.0.0",
                        "Severity": None,
                    }
                ],
            }
        ]
    }
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.53.0",
        coverage=SignalCoverage.COMPLETE,
    )
    assert signals[0].severity.raw == "UNKNOWN"
    assert signals[0].severity.normalized == NormalizedSeverity.INFO


def test_trivy_adapter_treats_null_results_as_empty_not_a_crash():
    # Real bug found via independent review: {"Results": null} used to crash
    # with TypeError: 'NoneType' object is not iterable — dict.get(key, [])
    # only substitutes on a MISSING key, not a present-but-null one.
    raw = {"Results": None}
    skipped = []
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.58.0",
        coverage=SignalCoverage.COMPLETE,
        on_skip=skipped.append,
    )
    assert signals == []
    assert len(skipped) == 1
    assert "Results" in skipped[0]


def test_trivy_adapter_null_vulnerabilities_in_one_result_does_not_lose_signals_from_another():
    # Sharper version of the bug above: a null container buried in ONE
    # result entry must not discard signals already parsed from OTHER,
    # perfectly valid result entries in the same report — the exact "must
    # not lose the other valid entries" contract (base.py's docstring).
    raw = {
        "Results": [
            {"Target": "app-a.py", "Vulnerabilities": None},
            {
                "Target": "app-b.py",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1111",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "Severity": "HIGH",
                    }
                ],
            },
        ]
    }
    skipped = []
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.58.0",
        coverage=SignalCoverage.COMPLETE,
        on_skip=skipped.append,
    )
    assert [s.rule.id for s in signals] == ["CVE-2024-1111"]
    assert any("Vulnerabilities" in msg for msg in skipped)


def test_trivy_adapter_null_secrets_does_not_warn_when_key_is_simply_absent():
    # A result with Vulnerabilities but no "Secrets" key at all is a normal,
    # everyday shape (not every Trivy result has secrets) — must NOT warn,
    # unlike a "Secrets": null (present but wrong type), which should.
    raw = {
        "Results": [
            {
                "Target": "app.py",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-2222",
                        "PkgName": "flask",
                        "InstalledVersion": "1.0",
                        "Severity": "LOW",
                    }
                ],
                # no "Secrets" key at all
            }
        ]
    }
    skipped = []
    signals = TrivyAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="0.58.0",
        coverage=SignalCoverage.COMPLETE,
        on_skip=skipped.append,
    )
    assert [s.rule.id for s in signals] == ["CVE-2024-2222"]
    assert skipped == []
