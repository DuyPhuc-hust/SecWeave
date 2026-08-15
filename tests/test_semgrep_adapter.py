import hashlib
from pathlib import Path

from hypothesis_engine.signal_normalizer.semgrep_adapter import SemgrepAdapter
from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from shared.models.signal import NormalizedSeverity, RawReference, SignalCoverage, SignalType

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_sample_report.json"


def test_semgrep_adapter_maps_fields_correctly():
    # FIXTURE is a real `semgrep scan --config=auto` run (see
    # .secweave/manual_test/ for the session that captured it) against the
    # real route handlers of OWASP Juice Shop (bkimminich/juice-shop) — not
    # hand-written. 13 real findings, including Juice Shop's actual, known
    # SQL-injection-via-Sequelize bugs in login.ts and search.ts.
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE),
        tool="semgrep",
        tool_version="1.172.0",
        coverage=SignalCoverage.COMPLETE,
    )

    assert len(signals) == 13
    assert all(s.source.tool == "semgrep" for s in signals)
    assert all(s.source.type == SignalType.SAST for s in signals)
    assert all(s.source.coverage == SignalCoverage.COMPLETE for s in signals)

    login_sqli = next(s for s in signals if "login.ts" in s.location.file_path)
    assert login_sqli.rule.id == (
        "javascript.sequelize.security.audit.sequelize-injection-express."
        "express-sequelize-injection"
    )
    assert login_sqli.rule.cwe == [
        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command "
        "('SQL Injection')"
    ]
    assert login_sqli.severity.raw == "ERROR"
    assert login_sqli.severity.normalized == NormalizedSeverity.HIGH
    assert login_sqli.location.start_line == 34
    assert login_sqli.location.end_line == 34
    # Real quirk, not a bug: Semgrep's free/anonymous CLI withholds the
    # actual matched code line behind a semgrep.dev login — "lines" (mapped
    # to signal_context) is literally this sentinel string, not real code.
    assert login_sqli.signal_context == "requires login"

    warning_signals = [s for s in signals if s.severity.raw == "WARNING"]
    error_signals = [s for s in signals if s.severity.raw == "ERROR"]
    assert len(warning_signals) == 9
    assert len(error_signals) == 4
    assert all(s.severity.normalized == NormalizedSeverity.MEDIUM for s in warning_signals)
    assert all(s.severity.normalized == NormalizedSeverity.HIGH for s in error_signals)


def test_semgrep_adapter_raw_reference_matches_file_hash():
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE), tool="semgrep", tool_version="1.78.0"
    )
    expected_hash = "sha256:" + hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert all(s.raw_reference.hash == expected_hash for s in signals)


def test_semgrep_adapter_does_not_invent_target_hint():
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(FIXTURE), tool="semgrep", tool_version="1.78.0"
    )
    assert all(s.target_hint.system_hint is None for s in signals)
    assert all(s.target_hint.component_hint is None for s in signals)


def test_semgrep_adapter_skips_malformed_entry_and_reports_it_via_on_skip():
    # 1 entry missing a required field ("path") among other valid entries —
    # must not let it lose the whole report, just skip that entry and report it.
    raw = {
        "results": [
            {"check_id": "good.rule.1", "path": "a.py", "start": {"line": 1}, "end": {"line": 1}},
            {"check_id": "bad.rule", "start": {"line": 1}, "end": {"line": 1}},  # missing "path"
            {"check_id": "good.rule.2", "path": "b.py", "start": {"line": 2}, "end": {"line": 2}},
        ]
    }
    skipped = []
    signals = SemgrepAdapter().parse(
        raw,
        RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="1.78.0",
        coverage=SignalCoverage.UNKNOWN,
        on_skip=skipped.append,
    )

    assert [s.rule.id for s in signals] == ["good.rule.1", "good.rule.2"]
    assert len(skipped) == 1
    assert "results[1]" in skipped[0]
    assert "semgrep" in skipped[0]


def test_semgrep_adapter_skips_entry_that_is_not_an_object():
    # results[1] is not an object (a string slipping in from a corrupted
    # report or a mismatched --tool) — must skip exactly that entry
    # (AttributeError when calling .get), not crash the whole report with a
    # traceback.
    raw = {
        "results": [
            {"check_id": "good.rule.1", "path": "a.py", "start": {"line": 1}, "end": {"line": 1}},
            "not an object",
            {"check_id": "good.rule.2", "path": "b.py", "start": {"line": 2}, "end": {"line": 2}},
        ]
    }
    skipped = []
    signals = SemgrepAdapter().parse(
        raw,
        RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="1.78.0",
        coverage=SignalCoverage.UNKNOWN,
        on_skip=skipped.append,
    )

    assert [s.rule.id for s in signals] == ["good.rule.1", "good.rule.2"]
    assert len(skipped) == 1
    assert "results[1]" in skipped[0]
