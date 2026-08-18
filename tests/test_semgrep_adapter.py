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


def test_semgrep_adapter_treats_null_results_as_empty_not_a_crash():
    # Real bug found via independent review: {"results": null} used to crash
    # with TypeError: 'NoneType' object is not iterable (dict.get(key, [])
    # only substitutes its default on a MISSING key, not a present-but-null
    # one) — this happened OUTSIDE the per-item try/except, so it wasn't
    # just one entry lost, it was the whole report.
    raw = {"results": None}
    skipped = []
    signals = SemgrepAdapter().parse(
        raw,
        RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="1.78.0",
        coverage=SignalCoverage.UNKNOWN,
        on_skip=skipped.append,
    )
    assert signals == []
    assert len(skipped) == 1
    assert "results" in skipped[0]


def test_semgrep_adapter_handles_custom_idor_rule_output_unchanged():
    # FIXTURE is a real `semgrep --config
    # scanner_rules/semgrep/idor_identity_from_url_param.yaml` run
    # (.venv/bin/semgrep 1.172.0) against the real, pinned OWASP NodeGoat
    # route handler app/routes/allocations.js (commit c5cb68a) — the exact
    # IDOR that Semgrep's own `--config auto` never flags (see
    # test_semgrep_adapter_maps_fields_correctly for that same file's
    # auto-config results, which contain no IDOR finding). Adapter code
    # requires zero changes for a custom local rule — same JSON shape as any
    # registry rule. Semgrep namespaces a local rule's id by its config
    # file's relative path, hence the "scanner_rules.semgrep." prefix below —
    # not a typo. Rule regenerated 2026-08-18 after an independent review
    # found real false positives (session check inside an `if` condition;
    # anonymous handlers) and a false negative (bracket-notation param
    # access, `req.params['userId']`) in the first version — all 3 fixed,
    # re-verified against synthetic if-condition/anonymous/bracket cases
    # before recapturing this fixture (see scanner_rules/README.md).
    fixture = Path(__file__).parent / "fixtures" / "nodegoat_idor_custom_rule_semgrep_report.json"
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(fixture), tool="semgrep", tool_version="1.172.0"
    )

    assert len(signals) == 1
    signal = signals[0]
    assert signal.rule.id.endswith("express-identity-from-url-param-without-session-check")
    assert signal.rule.cwe == ["CWE-639: Authorization Bypass Through User-Controlled Key"]
    assert signal.severity.raw == "ERROR"
    assert signal.severity.normalized == NormalizedSeverity.HIGH
    assert signal.location.file_path.endswith("allocations.js")
    assert signal.location.start_line == 16
    assert signal.location.end_line == 18


def test_semgrep_adapter_handles_custom_bola_rule_output_unchanged():
    # FIXTURE is a real `semgrep --config
    # scanner_rules/semgrep/bola_missing_auth_check.yaml` run against the
    # real, pinned VAmPI api_views/users.py (commit f16052d) — flags exactly
    # get_by_username (no token_validator call), and correctly stays silent
    # on the other username-taking view functions in the same file
    # (update_email, update_password, delete_user) that do call
    # token_validator — verified separately by re-running the rule against
    # the full file (1 finding, not 4) before this fixture was captured.
    # Rule regenerated 2026-08-18 after an independent review found a real
    # false negative (multi-parameter view functions, e.g. class-based
    # `def get(self, user_id)`) in the first version — fixed by also
    # matching `$ID` in any parameter position, not just as the sole
    # parameter (see scanner_rules/README.md).
    fixture = Path(__file__).parent / "fixtures" / "vampi_bola_custom_rule_semgrep_report.json"
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(fixture), tool="semgrep", tool_version="1.172.0"
    )

    assert len(signals) == 1
    signal = signals[0]
    assert signal.rule.id.endswith("flask-view-missing-auth-check-on-identity-param")
    assert signal.location.file_path.endswith("users.py")
    assert signal.location.start_line == 45


def test_idor_rule_stays_silent_when_session_check_is_inside_an_if_condition():
    # Regression for a real false positive an independent review found in
    # the first version of idor_identity_from_url_param.yaml: the exclusion
    # pattern only recognized `req.session` as its own bare statement, so
    # the single most natural way to write this check —
    #   const { userId } = req.params;
    #   if (req.session.userId !== userId) { return res.sendStatus(403); }
    # — still got flagged ERROR. Fixed by using Semgrep's deep-expression
    # ellipsis (`<... $REQ.session ...>`) so the exclusion looks for
    # req.session anywhere reachable, including inside a condition.
    fixture = Path(__file__).parent / "fixtures" / "idor_rule_regression_if_condition_guard.json"
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(fixture), tool="semgrep", tool_version="1.172.0"
    )
    assert signals == []


def test_idor_rule_stays_silent_on_anonymous_handlers_with_a_session_check():
    # Regression for a real false positive: the exclusion patterns only
    # recognized a NAMED function declaration or a named arrow assignment as
    # the enclosing handler, so the overwhelmingly common Express idiom of
    # passing an anonymous callback straight into router.get(...) —
    #   router.get('/x/:userId', function(req, res) { ... if (session
    #   check) ... })
    # — still got flagged even with a correct session check present. Fixed
    # by adding anonymous function-expression and anonymous arrow container
    # patterns alongside the named ones.
    fixture = Path(__file__).parent / "fixtures" / "idor_rule_regression_anonymous_handler.json"
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(fixture), tool="semgrep", tool_version="1.172.0"
    )
    assert signals == []


def test_idor_rule_catches_bracket_notation_param_access():
    # Regression for a real false negative: `req.params['userId']` (bracket
    # notation with a string-literal key) is genuinely vulnerable in exactly
    # the same way as `req.params.userId`, but the first rule version only
    # had a source pattern for dot-notation/destructuring. Fixed by adding
    # a `$REQ.params[$ID]` source pattern — and widening metavariable-regex
    # to accept the quotes Semgrep includes in the captured string-literal
    # metavariable text (`'userId'`, not `userId`).
    fixture = Path(__file__).parent / "fixtures" / "idor_rule_regression_bracket_notation.json"
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(fixture), tool="semgrep", tool_version="1.172.0"
    )
    assert len(signals) == 1
    assert signals[0].location.start_line == 2


def test_bola_rule_catches_multi_parameter_view_functions():
    # Regression for a real false negative: `def $FUNC($ID): ...` only
    # matched a view function whose identity parameter is its SOLE
    # parameter — missing both a class-based view method
    # (`def get(self, user_id): ...`) and a plain function with an extra
    # parameter (`def get_user_formatted(user_id, format): ...`), both
    # genuinely vulnerable (no token_validator call). Fixed by adding a
    # second pattern variant, `def $FUNC(..., $ID, ...): ...`, matching
    # $ID in any parameter position.
    fixture = Path(__file__).parent / "fixtures" / "bola_rule_regression_multiparam.json"
    normalizer = SignalNormalizer()
    signals = normalizer.normalize_file(
        report_path=str(fixture), tool="semgrep", tool_version="1.172.0"
    )
    assert len(signals) == 2
    assert {s.location.start_line for s in signals} == {2, 6}


def test_semgrep_adapter_null_result_does_not_lose_other_already_parsed_signals():
    # The real-world severity of the bug above: a null container anywhere
    # must not discard signals from OTHER, unrelated parts of the same
    # report. This test constructs the scenario at the orchestrator level
    # via a raw dict directly (results itself null means there's nothing
    # else in this report to lose) — see the Trivy equivalent test for the
    # "null buried among otherwise-valid data" case, which is the sharper
    # version of this same bug.
    raw = {"results": None}
    signals = SemgrepAdapter().parse(
        raw,
        RawReference(storage_path="in-memory", hash="sha256:0"),
        tool_version="1.78.0",
        coverage=SignalCoverage.UNKNOWN,
        on_skip=None,
    )
    assert signals == []  # did not raise
