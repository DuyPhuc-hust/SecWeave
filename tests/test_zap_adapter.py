from pathlib import Path

import pytest

from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from hypothesis_engine.signal_normalizer.zap_adapter import ZapAdapter
from shared.models.signal import NormalizedSeverity, RawReference, SignalCoverage, SignalType

FIXTURE = Path(__file__).parent / "fixtures" / "zap_sample_report.json"


def test_zap_adapter_maps_fields_correctly():
    # FIXTURE is a real `zap-baseline.py` run (see .secweave/manual_test/ for
    # the session that captured it) against the live OWASP Juice Shop
    # container — 1 real alert (Cross-Domain Misconfiguration), trimmed to
    # its first real instance — not hand-written.
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE),
        tool="owasp_zap",
        tool_version="2.17.0",
        coverage=SignalCoverage.PARTIAL,
    )

    assert len(signals) == 1
    signal = signals[0]

    assert signal.source.tool == "owasp_zap"
    assert signal.source.type == SignalType.DAST
    assert signal.source.coverage == SignalCoverage.PARTIAL
    assert signal.rule.id == "10098"
    assert signal.rule.cwe == ["CWE-264"]
    assert signal.severity.raw == "Medium (Medium)"
    assert signal.severity.normalized == NormalizedSeverity.MEDIUM
    assert signal.location.url == "http://host.docker.internal:3000"
    assert signal.location.http_method == "GET"
    assert signal.location.parameter is None
    assert signal.signal_context == "Access-Control-Allow-Origin: *"


def test_zap_adapter_evidence_field_is_never_named_evidence_in_output():
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE), tool="owasp_zap", tool_version="2.14.0"
    )
    schema = type(signals[0]).model_json_schema()
    assert "evidence" not in schema["properties"]


@pytest.mark.parametrize(
    "riskcode,expected",
    [
        ("0", NormalizedSeverity.INFO),
        ("1", NormalizedSeverity.LOW),
        ("2", NormalizedSeverity.MEDIUM),
        ("3", NormalizedSeverity.HIGH),
    ],
)
def test_zap_adapter_maps_riskcode_to_severity(riskcode, expected):
    from hypothesis_engine.signal_normalizer.zap_adapter import ZapAdapter

    raw = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "1",
                        "riskcode": riskcode,
                        "riskdesc": "irrelevant (Medium)",
                        "instances": [{"uri": "https://x/", "method": "GET"}],
                    }
                ]
            }
        ]
    }
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.UNKNOWN,
    )
    assert signals[0].severity.normalized == expected


def test_zap_adapter_ignores_legacy_risk_field_not_used_by_real_zap():
    # Regression: real ZAP has no plain "risk" field (only riskcode/riskdesc
    # — see SPEC §4.1.1: the SPEC's mapping table says "risk", but that's a
    # mix-up with the ZAP REST API /core/view/alerts, a different structure
    # from the site[].alerts[].instances[] this adapter uses). If someone
    # accidentally reintroduces a fake "risk" field, this test must confirm
    # it is NOT used to infer severity.
    from hypothesis_engine.signal_normalizer.zap_adapter import ZapAdapter

    raw = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "1",
                        "risk": "High",  # fake field, doesn't really exist in ZAP
                        "riskcode": "0",
                        "riskdesc": "Informational (Medium)",
                        "instances": [{"uri": "https://x/", "method": "GET"}],
                    }
                ]
            }
        ]
    }
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.UNKNOWN,
    )
    assert signals[0].severity.normalized == NormalizedSeverity.INFO
    assert signals[0].severity.raw == "Informational (Medium)"


def test_zap_adapter_skips_instance_missing_uri_and_reports_it_via_on_skip():
    # instances[0] is missing "uri", instances[1] is valid — only skip the
    # bad instance.
    raw = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "10202",
                        "riskcode": "1",
                        "riskdesc": "Low (Medium)",
                        "instances": [
                            {"method": "GET"},
                            {"uri": "https://x/ok", "method": "GET"},
                        ],
                    }
                ]
            }
        ]
    }
    skipped = []
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.UNKNOWN,
        on_skip=skipped.append,
    )

    assert len(signals) == 1
    assert signals[0].location.url == "https://x/ok"
    assert len(skipped) == 1
    assert "instances[0]" in skipped[0]
    assert "owasp_zap" in skipped[0]


def test_zap_adapter_skips_site_that_is_not_an_object():
    # site[0] is not an object (a string slipping in from a corrupted
    # report or a mismatched --tool) — must skip exactly that site, not
    # crash the whole report.
    raw = {
        "site": [
            "not an object",
            {
                "alerts": [
                    {
                        "pluginid": "10202",
                        "riskcode": "2",
                        "riskdesc": "Medium (Medium)",
                        "instances": [{"uri": "https://x/ok", "method": "GET"}],
                    }
                ]
            },
        ]
    }
    skipped = []
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.UNKNOWN,
        on_skip=skipped.append,
    )

    assert len(signals) == 1
    assert len(skipped) == 1
    assert "site[0]" in skipped[0]


def test_zap_adapter_skips_alert_that_is_not_an_object():
    raw = {
        "site": [
            {
                "alerts": [
                    "not an object",
                    {
                        "pluginid": "10202",
                        "riskcode": "2",
                        "riskdesc": "Medium (Medium)",
                        "instances": [{"uri": "https://x/ok", "method": "GET"}],
                    },
                ]
            }
        ]
    }
    skipped = []
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.UNKNOWN,
        on_skip=skipped.append,
    )

    assert len(signals) == 1
    assert len(skipped) == 1
    assert "alerts[0]" in skipped[0]


def test_zap_adapter_alert_with_no_instances_reports_via_on_skip():
    raw = {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "99",
                        "riskcode": "0",
                        "riskdesc": "Informational (Low)",
                        "instances": [],
                    }
                ]
            }
        ]
    }
    skipped = []
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.UNKNOWN,
        on_skip=skipped.append,
    )

    assert signals == []
    assert len(skipped) == 1
    assert "pluginid=99" in skipped[0]
    assert "không có instance nào" in skipped[0]


def test_zap_adapter_treats_null_site_as_empty_not_a_crash():
    # Real bug found via independent review: {"site": null} used to crash
    # with TypeError: 'NoneType' object is not iterable.
    raw = {"site": None}
    skipped = []
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.COMPLETE,
        on_skip=skipped.append,
    )
    assert signals == []
    assert len(skipped) == 1
    assert "site" in skipped[0]


def test_zap_adapter_treats_null_alerts_as_empty_not_a_crash():
    raw = {"site": [{"alerts": None}]}
    skipped = []
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.COMPLETE,
        on_skip=skipped.append,
    )
    assert signals == []
    assert any("alerts" in msg for msg in skipped)


def test_zap_adapter_treats_null_instances_as_empty_not_a_crash():
    # Real bug found via independent review: the code already correctly
    # called on_skip("không có instance nào...") for a falsy `instances`
    # value (since `not None` is True), then fell straight into
    # enumerate(instances) with no `continue` and crashed anyway.
    raw = {
        "site": [
            {
                "alerts": [
                    {"pluginid": "1", "alert": "Test Alert", "riskcode": "2", "riskdesc": "Medium (High)", "instances": None}
                ]
            }
        ]
    }
    skipped = []
    signals = ZapAdapter().parse(
        raw_report=raw,
        raw_reference=RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="2.14.0",
        coverage=SignalCoverage.COMPLETE,
        on_skip=skipped.append,
    )
    assert signals == []
    assert any("instances" in msg for msg in skipped)
