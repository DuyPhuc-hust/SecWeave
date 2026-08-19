import json
from pathlib import Path

import pytest

import cli

SEMGREP_FIXTURE = str(Path(__file__).parent / "fixtures" / "semgrep_sample_report.json")
ZAP_FIXTURE = str(Path(__file__).parent / "fixtures" / "zap_sample_report.json")


def test_cli_normalize_json_output(capsys):
    exit_code = cli.main(
        [
            "normalize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert len(data) == 13
    assert data[0]["rule"]["id"] == (
        "javascript.express.security.audit.express-detect-notevil-usage."
        "express-detect-notevil-usage"
    )
    assert data[0]["source"]["tool"] == "semgrep"


def test_cli_normalize_table_output(capsys):
    exit_code = cli.main(
        [
            "normalize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "express-detect-notevil-usage" in captured.out
    assert "13 NormalizedSignal" in captured.out


def test_cli_normalize_missing_file_returns_error_exit_code(capsys):
    exit_code = cli.main(
        [
            "normalize",
            "--signal",
            "does_not_exist.json",
            "--tool",
            "semgrep",
            "--tool-version",
            "1.0",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không tìm thấy file" in captured.err


def test_cli_normalize_invalid_tool_exits_nonzero():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "normalize",
                "--signal",
                SEMGREP_FIXTURE,
                "--tool",
                "sonarqube",
                "--tool-version",
                "1.0",
            ]
        )
    assert exc_info.value.code == 2


def test_cli_no_subcommand_exits_nonzero():
    with pytest.raises(SystemExit):
        cli.main([])


class _StubOpenAICompatibleClient:
    """Stands in for OpenAICompatibleLLMClient in CLI tests — makes no real
    API calls.

    CLI tests need to confirm the wiring (normalize -> engine -> print
    result) is correct, not that a real provider replies correctly — so the
    real class is monkeypatched with this stub, no LLM_API_KEY/LLM_BASE_URL/
    LLM_MODEL needed.
    """

    model = "stub-model"

    def generate(self, prompt: str) -> str:
        return json.dumps(
            {
                "verifiable": True,
                "expected_behavior": "a",
                "suspected_behavior": "b",
                "observation_criteria": "c",
            }
        )


def test_cli_hypothesize_json_output_with_stubbed_real_client(capsys, monkeypatch, tmp_path):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubOpenAICompatibleClient)

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--format",
            "json",
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert len(data) == 13
    assert data[0]["result"]["status"] == "hypothesis"
    assert data[0]["result"]["hypothesis"]["provenance"]["source_tool"] == "semgrep"
    assert "CẢNH BÁO" in captured.err


def test_cli_hypothesize_table_output_includes_provenance(capsys, monkeypatch, tmp_path):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubOpenAICompatibleClient)

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Provenance" in captured.out
    assert "source_tool=semgrep" in captured.out
    assert "source_signal_id=" in captured.out


def test_cli_hypothesize_records_hypothesis_to_context_store(capsys, monkeypatch, tmp_path):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubOpenAICompatibleClient)
    db_path = str(tmp_path / "test.db")

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    data = json.loads(capsys.readouterr().out)
    hypothesis_id = data[0]["result"]["hypothesis"]["hypothesis_id"]

    assert exit_code == 0

    show_exit_code = cli.main(
        [
            "show-hypothesis",
            "--hypothesis-id",
            hypothesis_id,
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    record = json.loads(capsys.readouterr().out)

    assert show_exit_code == 0
    assert record["hypothesis_id"] == hypothesis_id
    assert record["status"] == "hypothesis"
    # Real gap found via independent review: `location` used to come back
    # doubly-JSON-encoded (a string containing escaped JSON) from
    # show-hypothesis, while hypothesize returned the same logical field as
    # a real nested object — inconsistent shape for the same field across
    # 2 commands. Both must now agree.
    assert isinstance(record["location"], dict)
    assert record["location"] == data[0]["result"]["hypothesis"]["provenance"]["location"]


def test_cli_show_hypothesis_not_found_returns_error(capsys, tmp_path):
    exit_code = cli.main(
        [
            "show-hypothesis",
            "--hypothesis-id",
            "hyp_does_not_exist",
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không tìm thấy bản ghi nào" in captured.err


class _NotVerifiableStubClient:
    model = "stub-not-verifiable"

    def generate(self, prompt: str) -> str:
        return json.dumps({"verifiable": False, "reason": "không đủ ngữ cảnh"})


def test_cli_show_hypothesis_by_signal_id_finds_not_verifiable_record(
    capsys, monkeypatch, tmp_path
):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _NotVerifiableStubClient)
    db_path = str(tmp_path / "test.db")

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    data = json.loads(capsys.readouterr().out)
    signal_id = data[0]["signal_id"]

    assert exit_code == 0
    assert data[0]["result"]["status"] == "not_verifiable"

    # hypothesis_id doesn't exist for a not_verifiable record — must be
    # queryable via --signal-id, exactly the part that was just fixed.
    show_exit_code = cli.main(
        [
            "show-hypothesis",
            "--signal-id",
            signal_id,
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    records = json.loads(capsys.readouterr().out)

    assert show_exit_code == 0
    assert len(records) == 1
    assert records[0]["status"] == "not_verifiable"
    assert records[0]["hypothesis_id"] is None
    assert records[0]["reason"] == "không đủ ngữ cảnh"


def test_cli_hypothesize_bad_context_db_path_fails_cleanly(capsys, tmp_path):
    # Pointing --context-db at a directory (not a file) makes sqlite3.connect fail.
    bad_path = tmp_path / "not_a_file"
    bad_path.mkdir()

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--context-db",
            str(bad_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không mở được Context Store" in captured.err
    assert "Traceback" not in captured.err


def test_cli_hypothesize_context_db_parent_path_is_a_file_fails_cleanly(capsys, tmp_path):
    # Real gap found via independent review: this is a DIFFERENT failure
    # mode from the test above — here sqlite3.connect() never even runs,
    # because Path(db_path).parent.mkdir(...) itself raises a plain OSError
    # (the parent path component is an existing regular FILE, not a
    # directory). This used to escape the `except sqlite3.Error` around the
    # constructor entirely and dump a raw traceback.
    blocking_file = tmp_path / "not_a_dir"
    blocking_file.write_text("i am a file, not a directory")
    bad_path = blocking_file / "context.db"

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--context-db",
            str(bad_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không mở được Context Store" in captured.err
    assert "Traceback" not in captured.err


class _RaisingClient:
    model = "raising-model"

    def generate(self, prompt: str) -> str:
        raise RuntimeError("LLM provider unreachable")


def test_cli_hypothesize_llm_call_failure_is_reported_cleanly_not_as_traceback(
    capsys, monkeypatch, tmp_path
):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _RaisingClient)

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error: LLM provider unreachable" in captured.err
    assert "Traceback" not in captured.err


class _FlakyClient:
    """Succeeds on the first call, fails from the second call onward —
    simulates a signal in the middle hitting a network error after (an)
    earlier signal(s) already generated a hypothesis successfully.
    """

    model = "flaky-model"

    def __init__(self) -> None:
        self.call_count = 0

    def generate(self, prompt: str) -> str:
        self.call_count += 1
        if self.call_count == 1:
            return json.dumps(
                {
                    "verifiable": True,
                    "expected_behavior": "a",
                    "suspected_behavior": "b",
                    "observation_criteria": "c",
                }
            )
        raise RuntimeError("simulated failure on later signal")


def test_cli_hypothesize_persists_partial_success_before_later_failure(
    capsys, monkeypatch, tmp_path
):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _FlakyClient)
    db_path = str(tmp_path / "test.db")

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    # The run still reports an error (doesn't pretend to succeed)...
    assert exit_code == 1
    assert "error: simulated failure on later signal" in captured.err
    # ...but the first signal that already succeeded must still show up in the output...
    assert len(data) == 1
    hypothesis_id = data[0]["result"]["hypothesis"]["hypothesis_id"]
    # ...and was actually written to the Context Store, not thrown away.
    from context_store.store import SecurityContextStore

    store = SecurityContextStore(db_path=db_path)
    record = store.get_hypothesis(hypothesis_id)
    store.close()
    assert record is not None
    assert record["status"] == "hypothesis"


def test_cli_hypothesize_closes_context_store_even_on_early_failure(monkeypatch, tmp_path):
    for var in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)

    import context_store.store as store_module

    close_calls = []
    original_close = store_module.SecurityContextStore.close

    def _tracking_close(self):
        close_calls.append(True)
        original_close(self)

    monkeypatch.setattr(store_module.SecurityContextStore, "close", _tracking_close)

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )

    assert exit_code == 1
    assert close_calls == [True]


def test_cli_hypothesize_without_llm_env_vars_fails_cleanly(capsys, monkeypatch, tmp_path):
    for var in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "LLM_API_KEY" in captured.err


def test_cli_hypothesize_missing_source_file_returns_error(capsys):
    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--source",
            "does_not_exist.py",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không tìm thấy source file" in captured.err


def test_cli_hypothesize_source_pointing_at_a_directory_fails_cleanly(capsys, tmp_path):
    # Real gap found via independent review: only FileNotFoundError was
    # caught — --source pointing at a directory (a realistic CLI mistake,
    # e.g. a mistyped path) crashed with an uncaught IsADirectoryError
    # instead of this command's clean failure path.
    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--source",
            str(tmp_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không đọc được source file" in captured.err
    assert "Traceback" not in captured.err


def test_cli_hypothesize_source_with_non_utf8_content_fails_cleanly(capsys, tmp_path):
    binary_file = tmp_path / "binary.py"
    binary_file.write_bytes(b"\xff\xfe\x00\x01not valid utf-8")

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--source",
            str(binary_file),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không phải text UTF-8" in captured.err
    assert "Traceback" not in captured.err


def test_cli_hypothesize_agent_mode_batches_all_signals_into_one_wait(
    capsys, monkeypatch, tmp_path
):
    # SEMGREP_FIXTURE has 13 real findings (see its own comment) — confirms
    # all 13 are processed through EXACTLY 1 wait for the agent (not 13),
    # and all still get recorded correctly into the Context Store.
    import hypothesis_engine.llm_client.agent_bridge_client as agent_module

    wait_calls = []

    def _fake_wait(self, prompt_path, response_path):
        wait_calls.append(prompt_path)
        # Object keyed by string index "1".."13" — not a positional array —
        # since generate_many() now requires each answer to declare which
        # signal it's for, rather than trusting file order (see
        # agent_bridge_client.py's real mis-association fix).
        responses = {
            str(i): {
                "verifiable": True,
                "expected_behavior": "a",
                "suspected_behavior": "b",
                "observation_criteria": "c",
            }
            for i in range(1, 13)
        }
        responses["13"] = {"verifiable": False, "reason": "not enough context"}
        response_path.write_text(json.dumps(responses), encoding="utf-8")

    monkeypatch.setattr(agent_module.AgentBridgeLLMClient, "_wait_for_agent", _fake_wait)
    # AgentBridgeLLMClient() uses the default work_dir (".secweave_agent_bridge",
    # a relative path) — without chdir-ing into tmp_path, this would write real
    # files into the project's own .secweave_agent_bridge/ on every test run.
    monkeypatch.chdir(tmp_path)
    db_path = str(tmp_path / "test.db")

    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            SEMGREP_FIXTURE,
            "--tool",
            "semgrep",
            "--tool-version",
            "1.78.0",
            "--llm-mode",
            "agent",
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    data = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert len(wait_calls) == 1
    assert len(data) == 13
    assert data[0]["result"]["status"] == "hypothesis"
    assert data[-1]["result"]["status"] == "not_verifiable"


class _StubPlanLLMClient:
    model = "stub-plan-model"

    def generate(self, prompt: str) -> str:
        return json.dumps(
            {
                "plannable": True,
                "actions": [
                    {
                        "type": "read_only",
                        "method": "GET",
                        "target": "http://host.docker.internal:3000",
                        "description": "Read object 42 as owner identity.",
                    }
                ],
            }
        )


def _create_stored_hypothesis(capsys, monkeypatch, db_path: str) -> str:
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    # Uses the ZAP (DAST) fixture, not Semgrep/SAST: these `plan` CLI tests
    # exist to check plan-approval plumbing (allowlist, table/json output,
    # agent mode), and _StubPlanLLMClient below fabricates a plan targeting
    # "host.docker.internal:3000" — exploit_agent.agent's deterministic
    # anti-fabrication backstop would (correctly) reject that same target
    # for a SAST-sourced hypothesis, since SastLocation carries no url at
    # all for it to trace back to. The ZAP fixture's real uri already IS
    # host.docker.internal:3000 (real Juice Shop baseline scan — see
    # tests/fixtures/zap_sample_report.json), so provenance.location is a
    # genuine DastLocation and the backstop doesn't apply — matching what
    # these tests are actually about.
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubOpenAICompatibleClient)
    exit_code = cli.main(
        [
            "hypothesize",
            "--signal",
            ZAP_FIXTURE,
            "--tool",
            "owasp_zap",
            "--tool-version",
            "2.14.0",
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0
    return json.loads(capsys.readouterr().out)[0]["result"]["hypothesis"]["hypothesis_id"]


def test_cli_plan_not_found_hypothesis_id_returns_error(capsys, tmp_path):
    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            "hyp_does_not_exist",
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không tìm thấy hypothesis_id" in captured.err


def test_cli_plan_stored_hypothesis_missing_location_reports_clean_error(capsys, tmp_path):
    # Real regression: a hypothesis record saved before Context Store had the
    # "location" field (location=NULL) used to make `plan` crash with a raw
    # traceback (json.loads(None)) instead of a clean error.
    from context_store.store import SecurityContextStore

    db_path = str(tmp_path / "test.db")
    store = SecurityContextStore(db_path=db_path)
    store._conn.execute(
        "INSERT INTO hypotheses (hypothesis_id, signal_id, source_tool, status, "
        "expected_behavior, suspected_behavior, observation_criteria, coverage, location, created_at) "
        "VALUES (?, ?, ?, 'hypothesis', ?, ?, ?, ?, NULL, ?)",
        ("hyp_old", "sig_old", "semgrep", "a", "b", "c", "unknown", "2026-01-01T00:00:00Z"),
    )
    store._conn.commit()
    store.close()

    exit_code = cli.main(["plan", "--hypothesis-id", "hyp_old", "--context-db", db_path])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "được lưu trước khi Context Store có field 'location'" in captured.err
    assert "Traceback" not in captured.err


def test_cli_plan_approves_when_action_matches_allowlist(capsys, monkeypatch, tmp_path):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)
    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    data = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert data["plan_result"]["status"] == "planned"
    assert data["review"]["approved"] is True
    assert data["review"]["plan_check"]["approved"] is True
    assert data["review"]["cost_check"]["allowed"] is True


def test_cli_plan_blocks_when_action_outside_allowlist(capsys, monkeypatch, tmp_path):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)
    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            # No --allowed-action passed -> empty allowlist -> every action is blocked.
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    data = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert data["review"]["approved"] is False
    assert data["review"]["plan_check"]["approved"] is False


def test_cli_plan_table_output_shows_per_action_verdict(capsys, monkeypatch, tmp_path):
    # Regression: the table-print path (not json) used to crash because of
    # `review.checks` being wrong — it should be `review.plan_check.checks`.
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)
    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "[PASS]" in captured.out
    assert "APPROVED" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


class _StubNotPlannableLLMClient:
    model = "stub-not-plannable"

    def generate(self, prompt: str) -> str:
        return json.dumps({"plannable": False, "reason": "observation_criteria quá mơ hồ"})


def test_cli_plan_reports_not_plannable(capsys, monkeypatch, tmp_path):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubNotPlannableLLMClient)
    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "NOT_PLANNABLE" in captured.out
    assert "mơ hồ" in captured.out


def test_cli_plan_agent_mode_uses_agent_bridge_client(capsys, monkeypatch, tmp_path):
    import hypothesis_engine.llm_client.agent_bridge_client as agent_module
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    wait_calls = []

    def _fake_wait(self, prompt_path, response_path):
        wait_calls.append(prompt_path)
        response_path.write_text(
            json.dumps(
                {
                    "plannable": True,
                    "actions": [
                        {
                            "type": "read_only",
                            "method": "GET",
                            "target": "http://host.docker.internal:3000",
                            "description": "Read object 42.",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(agent_module.AgentBridgeLLMClient, "_wait_for_agent", _fake_wait)
    # Ensures the test doesn't accidentally call a real API if the
    # --llm-mode branch is picked wrong.
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _RaisingClient)
    monkeypatch.chdir(tmp_path)

    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--llm-mode",
            "agent",
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert len(wait_calls) == 1
    assert "APPROVED" in captured.out
    assert "Traceback" not in captured.out


def test_cli_plan_llm_call_failure_is_reported_cleanly_not_as_traceback(
    capsys, monkeypatch, tmp_path
):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _RaisingClient)
    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error: LLM provider unreachable" in captured.err
    assert "Traceback" not in captured.err


# ----- `execute` / `kill` — Kill-switch/CostService/EvidenceHarness wired
# into the CLI for the first time (real gap found via whole-project review:
# these 3 components existed only as tested library code + throwaway manual
# scripts, never a real CLI entrypoint). -----


def _patch_evidence_harness_transport(monkeypatch, handler):
    import evidence_harness.harness as harness_module
    import httpx

    real_client_class = httpx.Client  # captured BEFORE patching — see below
    monkeypatch.setattr(
        harness_module.httpx,
        "Client",
        # Must NOT reference httpx.Client by name inside this lambda: this
        # setattr call patches httpx.Client (the module attribute) itself,
        # so httpx.Client(...) evaluated later, inside the lambda's own
        # body, would resolve to this SAME lambda (infinite self-reference)
        # instead of the real class — use the reference captured above.
        lambda: real_client_class(transport=httpx.MockTransport(handler)),
    )


def test_cli_execute_captures_evidence_for_approved_actions(capsys, monkeypatch, tmp_path):
    import httpx

    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "granted" in captured.out
    assert "Verdict: inconclusive" in captured.out  # only role=main captured, no controls
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


def test_cli_execute_blocked_when_action_outside_allowlist_sends_no_real_request(
    capsys, monkeypatch, tmp_path
):
    import httpx

    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            # No --allowed-action -> empty allowlist -> BLOCKED before anything executes.
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "BLOCKED" in captured.out
    assert calls == []  # no real request was ever sent


def test_cli_execute_stops_when_cost_cap_is_reached(capsys, monkeypatch, tmp_path):
    import httpx

    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--cap",
            "0",  # the plan's 1 action would be the 1st — already over a cap of 0
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    # cap=0 also fails the PLANNING-time cost check (review.cost_check),
    # so this is refused as BLOCKED before ever reaching CostService/the
    # real network call — consistent with `plan`'s own existing behavior.
    assert exit_code == 1
    assert "BLOCKED" in captured.out
    assert calls == []


def test_cli_kill_stops_an_already_running_execution(capsys, tmp_path):
    from shared.kill_switch import ExecutionStatus, KillSwitch

    storage_dir = str(tmp_path / "evidence")
    kill_switch = KillSwitch(execution_id="exec_cli_kill_test", storage_dir=storage_dir)
    kill_switch.start()

    exit_code = cli.main(
        [
            "kill",
            "--execution-id",
            "exec_cli_kill_test",
            "--storage-dir",
            storage_dir,
            "--source",
            "operator",
            "--reason",
            "manual test stop",
            "--actor",
            "test-operator",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "stop" in captured.out
    assert kill_switch.status == ExecutionStatus.RUNNING  # the ORIGINAL instance hasn't refreshed yet

    kill_switch.refresh()
    assert kill_switch.status == ExecutionStatus.STOPPED  # now picks up the CLI's stop


def test_cli_kill_rejects_automatic_threshold_without_a_reason(capsys, tmp_path):
    exit_code = cli.main(
        [
            "kill",
            "--execution-id",
            "exec_cli_kill_test2",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--source",
            "automatic_threshold",
            "--reason",
            "cap exceeded",
            # missing --automatic-threshold-reason
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "automatic_threshold_reason" in captured.err or "error" in captured.err


def test_cli_execute_stops_mid_run_when_killed_by_a_separate_process(capsys, monkeypatch, tmp_path):
    # The actual end-to-end proof this whole increment exists for: an
    # execution started by `execute` genuinely reacts to a `kill` command
    # issued from what this test simulates as a SEPARATE process (its own
    # KillSwitch instance, invoked via cli.main() from inside the mock
    # transport handler — i.e. "something else called `secweave kill`
    # between these 2 real requests").
    import httpx

    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    class _StubTwoActionPlanLLMClient:
        model = "stub-two-action-plan"

        def generate(self, prompt: str) -> str:
            return json.dumps(
                {
                    "plannable": True,
                    "actions": [
                        {
                            "type": "read_only",
                            "method": "GET",
                            "target": "http://host.docker.internal:3000",
                            "description": "First action.",
                        },
                        {
                            "type": "read_only",
                            "method": "GET",
                            "target": "http://host.docker.internal:3000",
                            "description": "Second action — must never actually be sent.",
                        },
                    ],
                }
            )

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubTwoActionPlanLLMClient)

    storage_dir = str(tmp_path / "evidence")
    execution_id = "exec_cli_cross_process_kill"
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            # Simulates an operator, in a separate terminal/process, running
            # `secweave kill` right after the first action goes out.
            kill_exit_code = cli.main(
                [
                    "kill",
                    "--execution-id",
                    execution_id,
                    "--storage-dir",
                    storage_dir,
                    "--source",
                    "operator",
                    "--reason",
                    "operator aborts from another process",
                ]
            )
            assert kill_exit_code == 0
        return httpx.Response(200)

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--cap",
            "10",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            storage_dir,
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert len(calls) == 1  # the 2nd action's real request was never sent
    assert "DỪNG GIỮA CHỪNG" in captured.err
    assert "STOPPED" in captured.out or "stopped" in captured.out.lower()


def _execute_args(hypothesis_id, db_path, storage_dir, execution_id="exec_reuse_test", **overrides):
    args = [
        "execute",
        "--hypothesis-id",
        hypothesis_id,
        "--allowed-action",
        "GET http://host.docker.internal:3000",
        "--cap",
        str(overrides.pop("cap", 10)),
        "--target-id",
        "tgt_test",
        "--target-revision-id",
        "rev_test",
        "--execution-id",
        execution_id,
        "--storage-dir",
        storage_dir,
        "--context-db",
        db_path,
    ]
    return args


def test_cli_execute_reusing_a_running_executions_id_does_not_crash(capsys, monkeypatch, tmp_path):
    # Real HIGH-severity gap found via independent review: kill_switch.
    # start() used to be called unconditionally — the SECOND `execute`
    # invocation against an execution_id whose FIRST invocation already
    # succeeded (leaving it RUNNING — nothing yet drives it to COMPLETED)
    # crashed uncaught with a raw ValueError, even though reusing an
    # execution_id across multiple `execute` calls is exactly how
    # CostService's cap is meant to accumulate real meaning.
    import httpx

    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    _patch_evidence_harness_transport(monkeypatch, handler)
    storage_dir = str(tmp_path / "evidence")

    exit_code_1 = cli.main(_execute_args(hypothesis_id, db_path, storage_dir, cap=10))
    assert exit_code_1 == 0
    capsys.readouterr()

    exit_code_2 = cli.main(_execute_args(hypothesis_id, db_path, storage_dir, cap=10))
    captured_2 = capsys.readouterr()

    assert exit_code_2 == 0
    assert "Traceback" not in captured_2.err
    assert len(calls) == 2  # both invocations' actions were actually sent


def test_cli_execute_runtime_cost_cap_actually_refuses_the_real_request_on_reuse(
    capsys, monkeypatch, tmp_path
):
    # Real gap found via independent review: the ORIGINAL test with "cost
    # cap" in its name only exercised the PLANNING-time check (cap=0 fails
    # before CostService is ever constructed) — the actual RUNTIME
    # CostService enforcement path was unreachable through `execute` at
    # all before execution_id reuse was fixed (see the test above), since
    # a single invocation's own action count can never exceed its own cap.
    # This proves the real path: 2 invocations sharing one execution_id,
    # cap=1 — the 2nd invocation's action must be refused BEFORE a real
    # request is sent, and the kill-switch must auto-stop.
    import httpx

    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    _patch_evidence_harness_transport(monkeypatch, handler)
    storage_dir = str(tmp_path / "evidence")

    exit_code_1 = cli.main(_execute_args(hypothesis_id, db_path, storage_dir, cap=1))
    assert exit_code_1 == 0
    assert len(calls) == 1
    capsys.readouterr()

    exit_code_2 = cli.main(_execute_args(hypothesis_id, db_path, storage_dir, cap=1))
    captured_2 = capsys.readouterr()

    assert exit_code_2 == 1
    assert len(calls) == 1  # the 2nd invocation's action was refused BEFORE any real request
    assert "DỪNG GIỮA CHỪNG" in captured_2.err
    assert "stopped" in captured_2.out.lower()


def test_cli_execute_refuses_to_continue_a_stopped_execution(capsys, monkeypatch, tmp_path):
    import httpx

    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    _patch_evidence_harness_transport(monkeypatch, handler)
    storage_dir = str(tmp_path / "evidence")
    execution_id = "exec_stopped_test"

    exit_code_1 = cli.main(_execute_args(hypothesis_id, db_path, storage_dir, execution_id=execution_id))
    assert exit_code_1 == 0
    capsys.readouterr()

    kill_exit_code = cli.main(
        ["kill", "--execution-id", execution_id, "--storage-dir", storage_dir, "--source", "operator",
         "--reason", "test stop"]
    )
    assert kill_exit_code == 0
    capsys.readouterr()

    exit_code_2 = cli.main(_execute_args(hypothesis_id, db_path, storage_dir, execution_id=execution_id))
    captured_2 = capsys.readouterr()

    assert exit_code_2 == 1
    assert "resume" in captured_2.err.lower()
    assert len(calls) == 1  # the 2nd invocation never sent anything


def test_cli_resume_allows_execute_to_continue_after_a_kill(capsys, monkeypatch, tmp_path):
    import httpx

    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    _patch_evidence_harness_transport(monkeypatch, handler)
    storage_dir = str(tmp_path / "evidence")
    execution_id = "exec_resume_test"

    cli.main(_execute_args(hypothesis_id, db_path, storage_dir, execution_id=execution_id))
    capsys.readouterr()
    cli.main(
        ["kill", "--execution-id", execution_id, "--storage-dir", storage_dir, "--source", "operator",
         "--reason", "test stop"]
    )
    capsys.readouterr()

    resume_exit_code = cli.main(
        [
            "resume",
            "--execution-id",
            execution_id,
            "--storage-dir",
            storage_dir,
            "--authorization-reference",
            "owner re-approved via email 2026-08-17",
        ]
    )
    resume_captured = capsys.readouterr()
    assert resume_exit_code == 0
    assert "resume" in resume_captured.out.lower()

    exit_code_3 = cli.main(_execute_args(hypothesis_id, db_path, storage_dir, execution_id=execution_id))
    captured_3 = capsys.readouterr()

    assert exit_code_3 == 0
    assert "Traceback" not in captured_3.err
    assert len(calls) == 2  # 1st execute + the resumed execute both actually sent


def test_cli_kill_warns_when_execution_id_has_no_prior_history(capsys, tmp_path):
    # Real gap found via independent review: a mistyped/never-started
    # --execution-id used to report full, indistinguishable success —
    # output textually identical to a real successful stop.
    exit_code = cli.main(
        [
            "kill",
            "--execution-id",
            "exec_never_started_typo",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--source",
            "operator",
            "--reason",
            "oops, probably a typo",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0  # still succeeds (stopping from PREPARED is legitimate) — but with a warning
    assert "CẢNH BÁO" in captured.err
    assert "KHÔNG có lịch sử" in captured.err


def test_cli_kill_no_warning_when_execution_actually_had_prior_history(capsys, tmp_path):
    from shared.kill_switch import KillSwitch

    storage_dir = str(tmp_path / "evidence")
    ks = KillSwitch(execution_id="exec_real_history", storage_dir=storage_dir)
    ks.start()

    exit_code = cli.main(
        [
            "kill",
            "--execution-id",
            "exec_real_history",
            "--storage-dir",
            storage_dir,
            "--source",
            "operator",
            "--reason",
            "real stop",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "CẢNH BÁO" not in captured.err


# ----- `execute --plan-file` — real gap found via manual end-to-end testing
# against a live target: cmd_execute used to ALWAYS call agent.plan() fresh,
# a non-deterministic LLM call, so a plan a human reviewed via `secweave
# plan` beforehand wasn't necessarily what actually got executed. -----


def test_cli_execute_with_plan_file_never_calls_the_llm(capsys, monkeypatch, tmp_path):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    # Produce a real plan file via the actual `plan` command first.
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)
    plan_exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    assert plan_exit_code == 0
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(capsys.readouterr().out, encoding="utf-8")

    # Now point OpenAICompatibleLLMClient at something that CRASHES if ever
    # called — proves --plan-file genuinely never touches the LLM again.
    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _RaisingClient)

    import httpx

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "ĐÓNG BĂNG" in captured.out
    assert len(calls) == 1  # the frozen plan's 1 action was actually sent
    assert "Traceback" not in captured.err


def test_cli_execute_sensitive_param_redacts_value_from_the_stored_transcript(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: capture() has always accepted
    # sensitive_body_keys (caller-declared parameter names whose VALUES
    # never get written to the raw evidence transcript), but cmd_execute
    # never passed anything through it — a secret-shaped value in
    # ActionSpec.parameters (a password field, an API key) landed in the
    # on-disk artifact in plaintext, permanently, with no way to mark it.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_sensitive_test"
    storage_dir = tmp_path / "evidence"

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/login",
                                "description": "d",
                                "parameters": {"username": "tester", "password": "supersecret123"},
                            }
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "POST http://host.docker.internal:3000/login params:username,password",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
            "--sensitive-param",
            "password",
        ]
    )
    assert exit_code == 0

    transcripts = list((storage_dir / execution_id).glob("obs_*.json"))
    assert len(transcripts) == 1
    stored = transcripts[0].read_text(encoding="utf-8")
    assert "supersecret123" not in stored
    assert "tester" in stored  # non-sensitive fields still stored in the clear


def test_cli_execute_persists_structured_observations_alongside_the_raw_transcript(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: capture() returns a structured
    # NormalizedObservation, but cmd_execute only ever used it in-memory
    # (for decide()) and never persisted it — only the raw transcript
    # landed on disk, in a shape missing execution_id/target_id/
    # target_revision_id/channel/raw_evidence_hash/access_result. That left
    # no path to reconstruct observations for a later VerificationPackage
    # assembly. observations.jsonl closes that gap.
    from shared.models.observation import NormalizedObservation

    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_persist_test"
    storage_dir = tmp_path / "evidence"

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {"type": "read_only", "method": "GET", "target": "http://host.docker.internal:3000", "description": "d"}
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0

    log_path = storage_dir / execution_id / "observations.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    observation = NormalizedObservation(**json.loads(lines[0]))
    assert observation.execution_id == execution_id
    assert observation.target_id == "tgt_test"
    assert observation.target_revision_id == "rev_test"
    assert observation.status_code == 200


def test_cli_execute_captures_each_action_with_its_own_plan_assigned_role(capsys, monkeypatch, tmp_path):
    # Real gap closed 2026-08-19: cmd_execute used to hardcode role=main for
    # EVERY action regardless of what the plan said — a 3-role scenario
    # (main/positive_control/denied_control) tagged by Exploit Agent would
    # have every one of its observations silently mislabeled as main. This
    # asserts the plan's own per-action `role` now flows through untouched.
    from shared.models.observation import NormalizedObservation

    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_role_tagging_test"
    storage_dir = tmp_path / "evidence"

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000",
                                "description": "Positive control: the owner reads their own resource.",
                                "role": "positive_control",
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000",
                                "description": "Denied control: an unrelated identity is correctly denied.",
                                "role": "denied_control",
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0

    log_path = storage_dir / execution_id / "observations.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    observations = [NormalizedObservation(**json.loads(line)) for line in lines]
    assert [o.role.value for o in observations] == ["positive_control", "denied_control"]


# ----- --role-identity / --identity-logins: multi-identity 3-role scenarios (2026-08-19) -----


def _multi_identity_plan_file(tmp_path, hypothesis_id: str) -> Path:
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/resource",
                                "description": "Positive control: owner reads their own resource.",
                                "role": "positive_control",
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/resource",
                                "description": "Denied control: attacker is correctly denied.",
                                "role": "denied_control",
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return plan_file


def test_cli_execute_role_identity_bad_format_fails_cleanly(capsys, monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _multi_identity_plan_file(tmp_path, hypothesis_id)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--role-identity",
            "positive_control_no_equals_sign",
            "--allowed-action",
            "GET http://host.docker.internal:3000/resource",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--role-identity" in captured.err


def test_cli_execute_role_identity_invalid_role_fails_cleanly(capsys, monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _multi_identity_plan_file(tmp_path, hypothesis_id)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--role-identity",
            "not_a_real_role=owner",
            "--allowed-action",
            "GET http://host.docker.internal:3000/resource",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--role-identity" in captured.err


def test_cli_execute_identity_logins_missing_file_fails_cleanly(capsys, monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _multi_identity_plan_file(tmp_path, hypothesis_id)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--identity-logins",
            str(tmp_path / "does_not_exist.json"),
            "--allowed-action",
            "GET http://host.docker.internal:3000/resource",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "identity-logins" in captured.err


def test_cli_execute_identity_logins_malformed_schema_fails_cleanly(capsys, monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _multi_identity_plan_file(tmp_path, hypothesis_id)

    logins_file = tmp_path / "logins.json"
    logins_file.write_text(json.dumps({"owner": {"method": "POST"}}), encoding="utf-8")  # missing target

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--identity-logins",
            str(logins_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000/resource",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "identity-logins" in captured.err


def test_cli_execute_multi_identity_login_and_role_routing(capsys, monkeypatch, tmp_path):
    # The scenario this whole feature exists for: 2 real identities, each
    # logged in via its own bearer-token-in-body login (the same real shape
    # OWASP Juice Shop uses — see .secweave/manual_test/
    # identity_scenario_example.py), routed to the plan's 2 differently-
    # roled actions purely by role — the plan itself never names an
    # identity, only a role (Exploit Agent "không tự lấy credential").
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_multi_identity_test"
    storage_dir = tmp_path / "evidence"
    plan_file = _multi_identity_plan_file(tmp_path, hypothesis_id)

    logins_file = tmp_path / "logins.json"
    logins_file.write_text(
        json.dumps(
            {
                "owner": {
                    "method": "POST",
                    "target": "http://host.docker.internal:3000/login",
                    "parameters": {"email": "owner@test", "password": "pw1"},
                    "token_json_path": "token",
                },
                "attacker": {
                    "method": "POST",
                    "target": "http://host.docker.internal:3000/login",
                    "parameters": {"email": "attacker@test", "password": "pw2"},
                    "token_json_path": "token",
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            body = json.loads(request.content)
            token = "owner-token" if body["email"] == "owner@test" else "attacker-token"
            return httpx.Response(200, json={"token": token})
        # /resource: owner's token is granted (their own data), attacker's is denied.
        auth = request.headers.get("Authorization")
        if auth == "Bearer owner-token":
            return httpx.Response(200, json={"data": "owner's resource"})
        return httpx.Response(403, json={"error": "forbidden"})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--role-identity",
            "positive_control=owner",
            "--role-identity",
            "denied_control=attacker",
            "--identity-logins",
            str(logins_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000/resource",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0

    log_path = storage_dir / execution_id / "observations.jsonl"
    from shared.models.observation import NormalizedObservation

    observations = [NormalizedObservation(**json.loads(line)) for line in log_path.read_text().splitlines()]
    # 2 logins (role=setup, identity label sorted: attacker before owner) +
    # 2 plan actions (in plan order: positive_control then denied_control).
    assert [(o.role.value, o.identity) for o in observations] == [
        ("setup", "attacker"),
        ("setup", "owner"),
        ("positive_control", "owner"),
        ("denied_control", "attacker"),
    ]
    by_role = {o.role.value: o for o in observations}
    assert by_role["positive_control"].access_result.value == "granted"
    assert by_role["denied_control"].access_result.value == "denied"


def test_cli_execute_role_identity_label_without_a_login_entry_runs_unauthenticated(
    capsys, monkeypatch, tmp_path
):
    # A label referenced by --role-identity but absent from --identity-logins
    # is a legitimate identity too (e.g. an anonymous, never-logged-in
    # denied_control) — it must just run with a fresh, unauthenticated
    # client, not error out for "missing" a login it never needed.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _multi_identity_plan_file(tmp_path, hypothesis_id)

    def handler(request: httpx.Request) -> httpx.Response:
        if "Authorization" in request.headers:
            return httpx.Response(200, json={"data": "should not happen"})
        return httpx.Response(401, json={"error": "unauthenticated"})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--role-identity",
            "denied_control=never_logged_in",
            "--allowed-action",
            "GET http://host.docker.internal:3000/resource",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0


def test_cli_execute_login_token_extraction_failure_is_a_clean_error_not_a_crash(
    capsys, monkeypatch, tmp_path
):
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _multi_identity_plan_file(tmp_path, hypothesis_id)

    logins_file = tmp_path / "logins.json"
    logins_file.write_text(
        json.dumps(
            {
                "owner": {
                    "method": "POST",
                    "target": "http://host.docker.internal:3000/login",
                    "parameters": {"email": "owner@test", "password": "pw1"},
                    # Deliberately wrong path — the real response only has "token", not "authentication.token".
                    "token_json_path": "authentication.token",
                }
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": "owner-token"})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--role-identity",
            "positive_control=owner",
            "--identity-logins",
            str(logins_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000/resource",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "login()" in captured.err
    assert "Traceback" not in captured.err


def test_cli_execute_skips_login_for_a_role_identity_not_used_by_this_plan(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: an earlier version filtered
    # identities_needing_login only by "referenced by --role-identity at
    # all", not by whether that role actually appears in THIS plan's own
    # actions — a --role-identity entry for a role the plan doesn't use
    # would still trigger a real login HTTP request (wasted cost-cap
    # budget, an unnecessary side effect) for an identity nothing here
    # would ever send an action as. This plan has ONLY a positive_control
    # action; --role-identity maps denied_control too, but "attacker"'s
    # login must never be attempted.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/resource",
                                "description": "Positive control: owner reads their own resource.",
                                "role": "positive_control",
                            }
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    logins_file = tmp_path / "logins.json"
    logins_file.write_text(
        json.dumps(
            {
                "owner": {
                    "method": "POST",
                    "target": "http://host.docker.internal:3000/login",
                    "parameters": {"email": "owner@test", "password": "pw1"},
                    "token_json_path": "token",
                },
                "attacker": {
                    "method": "POST",
                    "target": "http://host.docker.internal:3000/login",
                    "parameters": {"email": "attacker@test", "password": "pw2"},
                    "token_json_path": "token",
                },
            }
        ),
        encoding="utf-8",
    )

    login_calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            body = json.loads(request.content)
            login_calls.append(body["email"])
            return httpx.Response(200, json={"token": "owner-token" if body["email"] == "owner@test" else "x"})
        return httpx.Response(200, json={"data": "owner's resource"})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--role-identity",
            "positive_control=owner",
            "--role-identity",
            "denied_control=attacker",  # this role isn't used by the plan above
            "--identity-logins",
            str(logins_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000/resource",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0
    assert login_calls == ["owner@test"]  # attacker's login was never attempted


# ----- Blind marker seeding automation (2026-08-19) -----


def test_cli_execute_substitutes_blind_marker_and_satisfies_the_main_predicate(
    capsys, monkeypatch, tmp_path
):
    # The scenario this feature exists for: a role=setup action plants bait
    # data whose content is the FIXED placeholder Exploit Agent's prompt
    # teaches it to use; cli.py substitutes a REAL random marker before
    # anything (Policy Service, the real request) ever sees it; role=main
    # reads the same resource back and gets response_contains_marker=True,
    # request_contains_marker=False — the main predicate actually SATISFIED
    # instead of perpetually INSUFFICIENT_DATA.
    import re

    import httpx

    from shared.kill_switch import ExecutionStatus
    from shared.models.observation import NormalizedObservation
    from verdict_oracle.oracle import decide

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_blind_marker_test"
    storage_dir = tmp_path / "evidence"

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/notes",
                                "description": "Seed bait note with blind marker.",
                                "role": "setup",
                                "parameters": {"content": "{{SECWEAVE_BLIND_MARKER}}"},
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/notes/1",
                                "description": "Main: read the seeded note back via the suspected path.",
                                "role": "main",
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    seeded_content = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/notes":
            body = json.loads(request.content)
            seeded_content.append(body["content"])
            return httpx.Response(200, json={"id": 1})
        return httpx.Response(200, json={"content": seeded_content[0]})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "POST http://host.docker.internal:3000/notes params:content",
            "--allowed-action",
            "GET http://host.docker.internal:3000/notes/1",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0

    # The real marker actually sent is a random 32-hex-char string, never
    # the literal placeholder text.
    assert len(seeded_content) == 1
    real_marker = seeded_content[0]
    assert real_marker != "{{SECWEAVE_BLIND_MARKER}}"
    assert re.fullmatch(r"[0-9a-f]{32}", real_marker)

    log_path = storage_dir / execution_id / "observations.jsonl"
    observations = [NormalizedObservation(**json.loads(line)) for line in log_path.read_text().splitlines()]
    by_role = {o.role.value: o for o in observations}
    assert by_role["main"].response_contains_marker is True
    assert by_role["main"].request_contains_marker is False

    # The seed manifest holds the SAME real marker (idempotent per
    # execution_id — proof the throwaway generate_marker() call and the
    # real capture loop agree on one value).
    seed_manifest = json.loads((storage_dir / execution_id / "seed_manifest.json").read_text())
    assert seed_manifest["marker"] == real_marker

    # actions.json (persisted for a later assemble-package) holds the REAL
    # marker too, not the placeholder — proof substitution happened before
    # persistence, not after.
    actions_on_disk = json.loads((storage_dir / execution_id / "actions.json").read_text())
    setup_action = next(a for a in actions_on_disk if a["role"] == "setup")
    assert setup_action["parameters"]["content"] == real_marker

    result = decide(observations, execution_status=ExecutionStatus.COMPLETED)
    by_group = {r.group.value: r.status.value for r in result.predicate_results}
    assert by_group["main"] == "satisfied"
    # Overall verdict is still inconclusive — this test only wires 1 of the
    # 3 required predicate groups; SPEC requires all 3 for a final verdict.
    assert result.verdict.value == "inconclusive"


def test_cli_execute_without_the_placeholder_never_generates_or_passes_a_marker(
    capsys, monkeypatch, tmp_path
):
    # Backward compatibility: a plan that never uses the placeholder must
    # behave EXACTLY as before this feature existed — no seed_manifest.json
    # written at all, and main's marker fields stay None (insufficient_data,
    # not a false "unsatisfied").
    import httpx

    from shared.models.observation import NormalizedObservation

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_no_marker_test"
    storage_dir = tmp_path / "evidence"
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/notes/1",
                                "description": "Main: ordinary single-role read.",
                            }
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000/notes/1",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0
    assert not (storage_dir / execution_id / "seed_manifest.json").exists()

    log_path = storage_dir / execution_id / "observations.jsonl"
    observations = [NormalizedObservation(**json.loads(line)) for line in log_path.read_text().splitlines()]
    assert observations[0].response_contains_marker is None
    assert observations[0].request_contains_marker is None


def test_cli_execute_substitutes_a_blind_marker_nested_inside_a_list_parameter(
    capsys, monkeypatch, tmp_path
):
    # Real gap found via independent review: an earlier version of the
    # substitution only scanned TOP-LEVEL STRING values of
    # action.parameters — a placeholder nested inside a list/dict value
    # (a shape an imperfectly-obedient LLM could plausibly produce, e.g.
    # a "tags" array) would sail through un-substituted with no error,
    # silently sending the literal placeholder text to the real target.
    # This proves the fix: nested occurrences ARE now detected and
    # substituted.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_nested_marker_test"
    storage_dir = tmp_path / "evidence"

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/notes",
                                "description": "Seed bait note with a nested blind marker.",
                                "role": "setup",
                                "parameters": {"tags": ["public", "{{SECWEAVE_BLIND_MARKER}}"]},
                            }
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    seeded_tags = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seeded_tags.extend(body["tags"])
        return httpx.Response(200, json={"id": 1})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "POST http://host.docker.internal:3000/notes params:tags",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0
    assert seeded_tags[0] == "public"
    assert seeded_tags[1] != "{{SECWEAVE_BLIND_MARKER}}"
    import re

    assert re.fullmatch(r"[0-9a-f]{32}", seeded_tags[1])


# ----- Resource-ID-chaining: {{FROM_STEP:...}} (2026-08-19) -----


def test_cli_execute_resolves_from_step_reference_into_a_later_actions_target(
    capsys, monkeypatch, tmp_path
):
    # The scenario this feature exists for: a test_data_creation action
    # gets a server-assigned ID it couldn't know in advance; a later
    # action needs to read back exactly that resource, not a guessed one.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_from_step_test"
    storage_dir = tmp_path / "evidence"

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/notes",
                                "description": "Seed a note; the server assigns its real id.",
                                "role": "setup",
                                "step_id": "seed_note",
                                "parameters": {"content": "hello"},
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/notes/{{FROM_STEP:seed_note:id}}",
                                "description": "Read back exactly the note just created.",
                                "role": "main",
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    requested_paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path == "/notes":
            return httpx.Response(200, json={"id": 42})
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "POST http://host.docker.internal:3000/notes params:content",
            "--allowed-action",
            "GET http://host.docker.internal:3000/notes/{id}",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0
    # The real, server-assigned id was used — never the literal placeholder.
    assert requested_paths == ["/notes", "/notes/42"]

    # actions.json holds the RESOLVED target, not the unresolved
    # {{FROM_STEP:...}} text from the plan file.
    actions_on_disk = json.loads((storage_dir / execution_id / "actions.json").read_text())
    main_action = next(a for a in actions_on_disk if a["role"] == "main")
    assert main_action["target"] == "http://host.docker.internal:3000/notes/42"


def test_cli_execute_from_step_preserves_the_referenced_values_own_type_in_parameters(
    capsys, monkeypatch, tmp_path
):
    # A parameters value that's EXACTLY one {{FROM_STEP:...}} placeholder
    # (nothing else around it) resolves to the referenced value's OWN
    # JSON type — a real int stays an int, not a stringified "42".
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_from_step_type_test"
    storage_dir = tmp_path / "evidence"

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/notes",
                                "description": "Seed a note.",
                                "role": "setup",
                                "step_id": "seed_note",
                                "parameters": {"content": "hello"},
                            },
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/link",
                                "description": "Link something to the note by its real numeric id.",
                                "role": "main",
                                "parameters": {"note_id": "{{FROM_STEP:seed_note:id}}"},
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    seen_bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen_bodies.append(body)
        if request.url.path == "/notes":
            return httpx.Response(200, json={"id": 42})
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "POST http://host.docker.internal:3000/notes params:content",
            "--allowed-action",
            "POST http://host.docker.internal:3000/link params:note_id",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0
    assert seen_bodies[1] == {"note_id": 42}  # real int, not "42"


def test_cli_execute_from_step_referencing_an_unrun_step_id_fails_cleanly(capsys, monkeypatch, tmp_path):
    # A plan referencing a step_id that never ran (typo, or a forward/self
    # reference) must fail with a clean, specific error — never crash, and
    # never silently send the literal placeholder text to the real target.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/notes/{{FROM_STEP:never_ran:id}}",
                                "description": "References a step_id that doesn't exist.",
                            }
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000/notes/{id}",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "never_ran" in captured.err
    assert "Traceback" not in captured.err


def test_cli_execute_rejects_a_from_step_resolved_value_that_escapes_the_allowlist(
    capsys, monkeypatch, tmp_path
):
    # Real HIGH-severity gap found via independent review: review_plan()
    # only ever checks the UNRESOLVED plan — a {{FROM_STEP:...}} placeholder
    # has no "/" in it, so it always satisfies an `{id}`-style allowlist
    # entry's `[^/]+` regex regardless of what the REAL, runtime-resolved
    # value (sourced from a real response — exactly the kind of data an
    # IDOR-style plan reads, and can't fully trust) turns out to be. A
    # resolved value containing "/../.." could turn 1 allowed path segment
    # into several, escaping the reviewed scope with zero enforcement
    # unless the RESOLVED action is re-checked before the real request is
    # sent. This proves the fix: a step whose real response smuggles a
    # path-traversal payload into the id field is rejected, not silently
    # sent.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/notes",
                                "description": "Seed a note.",
                                "step_id": "seed_note",
                                "parameters": {"content": "hello"},
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/notes/{{FROM_STEP:seed_note:id}}",
                                "description": "Read back the note by its real id.",
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    real_requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        real_requests.append(str(request.url))
        if request.url.path == "/notes":
            # A real, attacker-influenced response smuggling a traversal
            # payload into the id field instead of an ordinary integer.
            return httpx.Response(200, json={"id": "42/../../admin/settings"})
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "POST http://host.docker.internal:3000/notes params:content",
            "--allowed-action",
            "GET http://host.docker.internal:3000/notes/{id}",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "không còn khớp allowlist" in captured.err
    # The seed action IS allowed and does go out, but the GET with the
    # escaping resolved value must NEVER reach the real target.
    assert real_requests == ["http://host.docker.internal:3000/notes"]


def test_cli_execute_rejects_a_step_id_reused_by_2_different_actions(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: nothing stopped 2 actions from
    # reusing the same step_id (an LLM mistake the prompt doesn't
    # explicitly forbid) — the SECOND one's response used to silently
    # clobber the first in step_responses, so a later FROM_STEP reference
    # would resolve to whichever same-labeled action happened to run more
    # recently, with no error. Must refuse instead of silently picking one.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/notes",
                                "description": "Seed note A.",
                                "step_id": "dup",
                                "parameters": {"content": "a"},
                            },
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/notes",
                                "description": "Seed note B, reusing the SAME step_id by mistake.",
                                "step_id": "dup",
                                "parameters": {"content": "b"},
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "POST http://host.docker.internal:3000/notes params:content",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "step_id='dup'" in captured.err
    assert "Traceback" not in captured.err


def test_cli_execute_from_step_referencing_a_non_scalar_in_target_fails_cleanly(
    capsys, monkeypatch, tmp_path
):
    # A json_path pointing at a nested object/list (not a scalar) can't be
    # meaningfully embedded in a URL string — must fail cleanly instead of
    # silently interpolating Python's dict repr into a real request.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/notes",
                                "description": "Seed a note.",
                                "step_id": "seed_note",
                                "parameters": {"content": "hello"},
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/notes/{{FROM_STEP:seed_note:owner}}",
                                "description": "Mistakenly references a nested object, not a scalar id.",
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/notes":
            return httpx.Response(200, json={"id": 1, "owner": {"name": "alice", "id": 7}})
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "POST http://host.docker.internal:3000/notes params:content",
            "--allowed-action",
            "GET http://host.docker.internal:3000/notes/{id}",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "dict" in captured.err
    assert "Traceback" not in captured.err


def test_cli_execute_plan_file_rejects_mismatched_hypothesis_id(capsys, monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": "hyp_this_one",
                "plan_result": {
                    "status": "planned",
                    "plan": {"hypothesis_id": "hyp_this_one", "actions": [
                        {"type": "read_only", "method": "GET", "target": "http://x/y", "description": "d"}
                    ]},
                },
            }
        ),
        encoding="utf-8",
    )

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            "hyp_a_different_one",
            "--plan-file",
            str(plan_file),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không khớp" in captured.err


def test_cli_execute_plan_file_rejects_mismatched_embedded_hypothesis_id(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: the ORIGINAL check only
    # compared the file's TOP-LEVEL hypothesis_id (what `plan --format
    # json` writes from --hypothesis-id at save time) against
    # --hypothesis-id — it never checked plan_result.plan.hypothesis_id,
    # the ActionPlan's OWN embedded field. A hand-edited/corrupted file
    # where these two disagree used to load and execute with zero error,
    # silently attributing another hypothesis's actions to this one.
    import httpx

    db_path = str(tmp_path / "test.db")
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": "hyp_this_one",  # matches --hypothesis-id below
                "plan_result": {
                    "status": "planned",
                    # ...but the embedded plan claims a DIFFERENT hypothesis_id
                    "plan": {"hypothesis_id": "hyp_a_totally_different_one", "actions": [
                        {"type": "read_only", "method": "GET", "target": "http://host.docker.internal:3000/mismatched",
                         "description": "d"}
                    ]},
                },
            }
        ),
        encoding="utf-8",
    )

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            "hyp_this_one",
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000/mismatched",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không khớp" in captured.err
    assert calls == []  # no real request was ever sent


def test_cli_execute_plan_file_missing_file_fails_cleanly(capsys, tmp_path):
    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            "hyp_x",
            "--plan-file",
            str(tmp_path / "does_not_exist.json"),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không tìm thấy plan file" in captured.err


def test_cli_execute_plan_file_invalid_json_fails_cleanly(capsys, tmp_path):
    plan_file = tmp_path / "plan.json"
    plan_file.write_text("not valid json {{{", encoding="utf-8")

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            "hyp_x",
            "--plan-file",
            str(plan_file),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không phải JSON hợp lệ" in captured.err


def test_cli_execute_plan_file_not_plannable_status_fails_cleanly(capsys, tmp_path):
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": "hyp_x",
                "plan_result": {"status": "not_plannable", "plan": None, "reason": "no endpoint"},
            }
        ),
        encoding="utf-8",
    )

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            "hyp_x",
            "--plan-file",
            str(plan_file),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "NOT_PLANNABLE" in captured.out


def test_cli_execute_plan_file_malformed_schema_fails_cleanly(capsys, tmp_path):
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps({"hypothesis_id": "hyp_x", "plan_result": {"status": "planned", "plan": {"actions": []}}}),
        encoding="utf-8",
    )

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            "hyp_x",
            "--plan-file",
            str(plan_file),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không đúng schema" in captured.err


def test_cli_assemble_package_builds_a_real_package_from_a_real_execute_run(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: assemble_verification_package()
    # was fully built/tested but had no CLI entrypoint at all — this closes
    # it, reading back exactly what a real `execute` run persists
    # (observations.jsonl/actions.json/execution_status.json), no
    # --plan-file needed at assembly time.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_assemble_test"
    storage_dir = tmp_path / "evidence"

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {"type": "read_only", "method": "GET", "target": "http://host.docker.internal:3000", "description": "d"}
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    execute_exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert execute_exit_code == 0
    capsys.readouterr()  # discard execute's own output

    exit_code = cli.main(
        [
            "assemble-package",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--environment",
            "sandbox",
            "--authorization-reference",
            "auth_local_test_1",
            "--scenario",
            "X-Content-Type-Options header missing on GET /",
            "--limitations",
            "Chỉ có role=main, thiếu positive/denied control.",
            "--next-action",
            "Không cần thêm — quan sát trực tiếp, không cần predicate 3 nhóm.",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    package = json.loads(captured.out)
    assert package["target_id"] == "tgt_test"
    assert package["revision"] == "rev_test"
    assert package["environment"] == "sandbox"
    assert package["authorization_reference"] == "auth_local_test_1"
    assert package["execution_id"] == execution_id
    assert len(package["normalized_observations"]) == 1
    assert len(package["action_record"]) == 1
    assert package["verdict"] == "inconclusive"  # only role=main, no controls


def test_cli_assemble_package_works_after_a_multi_identity_execute_run(capsys, monkeypatch, tmp_path):
    # Real gap found while running the whole pipeline live end-to-end
    # (not caught by any prior unit/CLI test): login()'s own ActionSpec is
    # built fresh inside _run_execute's login step with an
    # auto-generated action_id that never appears in
    # plan_result.plan.actions — before this fix, actions.json (persisted
    # right after the harness is built) never included it, so
    # assemble-package would reject the WHOLE package with "action_record
    # thiếu ActionSpec cho action_ref" the moment a plan used
    # --identity-logins at all. Also checks the login ActionSpec's OWN
    # `role` field: it used to default to MAIN (ActionSpec's default) even
    # though harness.login() always actually captures with role=SETUP —
    # a misleading action_record entry claiming role=main for an action
    # whose own observation says role=setup.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_assemble_multi_identity_test"
    storage_dir = tmp_path / "evidence"
    plan_file = _multi_identity_plan_file(tmp_path, hypothesis_id)

    logins_file = tmp_path / "logins.json"
    logins_file.write_text(
        json.dumps(
            {
                "owner": {
                    "method": "POST",
                    "target": "http://host.docker.internal:3000/login",
                    "parameters": {"email": "owner@test", "password": "pw1"},
                    "token_json_path": "token",
                },
                "attacker": {
                    "method": "POST",
                    "target": "http://host.docker.internal:3000/login",
                    "parameters": {"email": "attacker@test", "password": "pw2"},
                    "token_json_path": "token",
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            body = json.loads(request.content)
            token = "owner-token" if body["email"] == "owner@test" else "attacker-token"
            return httpx.Response(200, json={"token": token})
        auth = request.headers.get("Authorization")
        return httpx.Response(200 if auth == "Bearer owner-token" else 403, json={})

    _patch_evidence_harness_transport(monkeypatch, handler)

    execute_exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--role-identity",
            "positive_control=owner",
            "--role-identity",
            "denied_control=attacker",
            "--identity-logins",
            str(logins_file),
            "--allowed-action",
            "GET http://host.docker.internal:3000/resource",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert execute_exit_code == 0
    capsys.readouterr()

    exit_code = cli.main(
        [
            "assemble-package",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--environment",
            "sandbox",
            "--authorization-reference",
            "auth_local_test_1",
            "--scenario",
            "IDOR via multi-identity 3-role scenario",
            "--limitations",
            "x",
            "--next-action",
            "x",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0, captured.err
    package = json.loads(captured.out)
    assert len(package["action_record"]) == 4  # 2 plan actions + 2 login actions
    login_actions = [a for a in package["action_record"] if a["method"] == "POST" and a["target"].endswith("/login")]
    assert len(login_actions) == 2
    assert all(a["role"] == "setup" for a in login_actions)


def test_cli_assemble_package_fails_cleanly_when_execution_was_never_run(capsys, tmp_path):
    exit_code = cli.main(
        [
            "assemble-package",
            "--execution-id",
            "exec_never_ran",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--environment",
            "sandbox",
            "--authorization-reference",
            "auth_1",
            "--scenario",
            "x",
            "--limitations",
            "x",
            "--next-action",
            "x",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không tìm thấy" in captured.err


def test_cli_assemble_package_works_after_execute_is_called_twice_with_different_plans(
    capsys, monkeypatch, tmp_path
):
    # Real gap found via independent review: actions.json was written by
    # OVERWRITING (not merging), while observations.jsonl already
    # accumulates across multiple `execute` calls reusing one execution_id
    # (a supported pattern elsewhere — kill-switch RUNNING-continuation,
    # CostService cap accumulation). A 2nd `execute` call with a DIFFERENT
    # plan permanently lost the 1st call's ActionSpec from actions.json,
    # making `assemble-package` unconditionally fail afterward.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_two_plans_test"
    storage_dir = tmp_path / "evidence"

    def _plan_file(path, target):
        path.write_text(
            json.dumps(
                {
                    "hypothesis_id": hypothesis_id,
                    "plan_result": {
                        "status": "planned",
                        "plan": {
                            "hypothesis_id": hypothesis_id,
                            "actions": [{"type": "read_only", "method": "GET", "target": target, "description": "d"}],
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    plan_a = tmp_path / "plan_a.json"
    _plan_file(plan_a, "http://host.docker.internal:3000/a")
    plan_b = tmp_path / "plan_b.json"
    _plan_file(plan_b, "http://host.docker.internal:3000/b")

    for plan_file in (plan_a, plan_b):
        exit_code = cli.main(
            [
                "execute",
                "--hypothesis-id",
                hypothesis_id,
                "--plan-file",
                str(plan_file),
                "--allowed-action",
                "GET http://host.docker.internal:3000/a",
                "--allowed-action",
                "GET http://host.docker.internal:3000/b",
                "--target-id",
                "tgt_test",
                "--target-revision-id",
                "rev_test",
                "--execution-id",
                execution_id,
                "--storage-dir",
                str(storage_dir),
                "--context-db",
                db_path,
            ]
        )
        assert exit_code == 0
        capsys.readouterr()

    actions_on_disk = json.loads((storage_dir / execution_id / "actions.json").read_text(encoding="utf-8"))
    assert len(actions_on_disk) == 2  # both plans' actions kept, not just the 2nd call's

    exit_code = cli.main(
        [
            "assemble-package",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--environment",
            "sandbox",
            "--authorization-reference",
            "auth_1",
            "--scenario",
            "s",
            "--limitations",
            "l",
            "--next-action",
            "n",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    package = json.loads(captured.out)
    assert len(package["action_record"]) == 2
    assert len(package["normalized_observations"]) == 2


def _assemble_a_real_package(capsys, monkeypatch, tmp_path, execution_id="exec_review_test"):
    """Shared setup: run a real execute -> assemble-package, return the
    package JSON string and the storage dir, for review-package tests."""
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    storage_dir = tmp_path / "evidence"

    plan_file = tmp_path / "plan.json"
    plan_file.write_text(
        json.dumps(
            {
                "hypothesis_id": hypothesis_id,
                "plan_result": {
                    "status": "planned",
                    "plan": {
                        "hypothesis_id": hypothesis_id,
                        "actions": [
                            {"type": "read_only", "method": "GET", "target": "http://host.docker.internal:3000", "description": "d"}
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    assert (
        cli.main(
            [
                "execute",
                "--hypothesis-id",
                hypothesis_id,
                "--plan-file",
                str(plan_file),
                "--allowed-action",
                "GET http://host.docker.internal:3000",
                "--target-id",
                "tgt_test",
                "--target-revision-id",
                "rev_test",
                "--execution-id",
                execution_id,
                "--storage-dir",
                str(storage_dir),
                "--context-db",
                db_path,
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert (
        cli.main(
            [
                "assemble-package",
                "--execution-id",
                execution_id,
                "--storage-dir",
                str(storage_dir),
                "--target-id",
                "tgt_test",
                "--target-revision-id",
                "rev_test",
                "--environment",
                "sandbox",
                "--authorization-reference",
                "auth_1",
                "--scenario",
                "s",
                "--limitations",
                "l",
                "--next-action",
                "n",
                "--format",
                "json",
            ]
        )
        == 0
    )
    package_json = capsys.readouterr().out
    package_file = tmp_path / "package.json"
    package_file.write_text(package_json, encoding="utf-8")
    return package_file


def test_cli_review_package_release_requires_checked_raw_artifact_flag(capsys, monkeypatch, tmp_path):
    # SPEC §4.5: releasing requires having personally cross-checked >=1 raw
    # artifact — the CLI must refuse a release decision without this flag,
    # not silently accept a rubber-stamp.
    package_file = _assemble_a_real_package(capsys, monkeypatch, tmp_path)

    exit_code = cli.main(
        [
            "review-package",
            "--package-file",
            str(package_file),
            "--reviewer",
            "phuc@ntq.local",
            "--decision",
            "release",
            "--reason",
            "Looks good.",
            # deliberately no --checked-raw-artifact
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "checked_raw_artifact" in captured.err


def test_cli_review_package_release_with_checked_raw_artifact_succeeds(capsys, monkeypatch, tmp_path):
    from context_store.store import SecurityContextStore

    execution_id = "exec_release_promote_test"
    # Must match _assemble_a_real_package's own db_path — execute() already
    # wrote this execution's unverified observations there.
    context_db = str(tmp_path / "test.db")
    package_file = _assemble_a_real_package(capsys, monkeypatch, tmp_path, execution_id=execution_id)

    exit_code = cli.main(
        [
            "review-package",
            "--package-file",
            str(package_file),
            "--reviewer",
            "phuc@ntq.local",
            "--decision",
            "release",
            "--reason",
            "Cross-checked obs_1 against its raw transcript, matches.",
            "--checked-raw-artifact",
            "--context-db",
            context_db,
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    reviewed_package = json.loads(captured.out)
    assert reviewed_package["human_review_record"]["decision"] == "release"
    assert reviewed_package["human_review_record"]["checked_raw_artifact"] is True
    assert reviewed_package["human_review_record"]["reviewer"] == "phuc@ntq.local"
    # The command must never have touched the verdict itself.
    assert reviewed_package["verdict"] == "inconclusive"

    # SPEC §4.6 write path, step 2: releasing must promote this execution's
    # unverified observations to verified in the Context Store.
    store = SecurityContextStore(db_path=context_db)
    assert store.get_unverified_context("tgt_test") == []
    verified = store.get_verified_context("tgt_test")
    assert len(verified) == 1
    store.close()


def test_cli_review_package_reject_does_not_require_checked_raw_artifact(capsys, monkeypatch, tmp_path):
    # Rejecting/retesting a package is not "releasing" it — SPEC's hard
    # cross-check requirement is specifically about deciding to RELEASE.
    package_file = _assemble_a_real_package(capsys, monkeypatch, tmp_path)

    exit_code = cli.main(
        [
            "review-package",
            "--package-file",
            str(package_file),
            "--reviewer",
            "phuc@ntq.local",
            "--decision",
            "reject",
            "--reason",
            "Verdict is inconclusive, not enough evidence to ship.",
        ]
    )
    assert exit_code == 0


def test_cli_review_package_fails_cleanly_for_a_missing_package_file(capsys, tmp_path):
    exit_code = cli.main(
        [
            "review-package",
            "--package-file",
            str(tmp_path / "does_not_exist.json"),
            "--reviewer",
            "phuc@ntq.local",
            "--decision",
            "reject",
            "--reason",
            "x",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "không tìm thấy" in captured.err


def test_cli_review_package_rejects_a_hand_tampered_verdict(capsys, monkeypatch, tmp_path):
    # HIGH severity real bypass found via independent review: a package
    # file hand-edited to declare verdict=confirmed + matching (but
    # fabricated) predicate_results — while normalized_observations was
    # left untouched, still showing no real satisfying evidence — passed
    # every existing validator (they only check the package is INTERNALLY
    # consistent, never that predicate_results actually reflects the
    # observations it claims to summarize) and came out with a legitimate-
    # looking, decision=release human_review_record attached.
    package_file = _assemble_a_real_package(capsys, monkeypatch, tmp_path)
    package_data = json.loads(package_file.read_text(encoding="utf-8"))
    assert package_data["verdict"] == "inconclusive"  # sanity: real run, no controls captured

    package_data["verdict"] = "confirmed"
    package_data["verdict_reason"] = "FABRICATED"
    package_data["predicate_results"] = [
        {"group": "main", "status": "satisfied", "reason": "FABRICATED"},
        {"group": "positive_control", "status": "satisfied", "reason": "FABRICATED"},
        {"group": "denied_control", "status": "satisfied", "reason": "FABRICATED"},
    ]
    tampered_file = tmp_path / "tampered_package.json"
    tampered_file.write_text(json.dumps(package_data), encoding="utf-8")

    exit_code = cli.main(
        [
            "review-package",
            "--package-file",
            str(tampered_file),
            "--reviewer",
            "phuc@ntq.local",
            "--decision",
            "release",
            "--reason",
            "test",
            "--checked-raw-artifact",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "sửa tay" in captured.err


def test_cli_review_package_rejects_retest_reference_with_non_retest_decision(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: --retest-reference could be
    # attached to ANY decision (e.g. release), producing a package that's
    # simultaneously is_release_ready=True and carries a retest_reference —
    # contradicting field #19's own semantics ("absent until retests have
    # run").
    package_file = _assemble_a_real_package(capsys, monkeypatch, tmp_path)

    exit_code = cli.main(
        [
            "review-package",
            "--package-file",
            str(package_file),
            "--reviewer",
            "phuc@ntq.local",
            "--decision",
            "release",
            "--reason",
            "test",
            "--checked-raw-artifact",
            "--retest-reference",
            "retest_123",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "retest" in captured.err


def test_cli_review_package_warns_when_overwriting_a_prior_review(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: overwriting an existing
    # human_review_record (e.g. a prior REJECT) left zero trace it ever
    # existed. Not blocked (a legitimate re-review workflow exists), but
    # must be surfaced loudly.
    package_file = _assemble_a_real_package(capsys, monkeypatch, tmp_path)

    first_exit = cli.main(
        [
            "review-package",
            "--package-file",
            str(package_file),
            "--reviewer",
            "reviewerA",
            "--decision",
            "reject",
            "--reason",
            "not enough evidence",
            "--format",
            "json",
        ]
    )
    assert first_exit == 0
    package_file.write_text(capsys.readouterr().out, encoding="utf-8")

    second_exit = cli.main(
        [
            "review-package",
            "--package-file",
            str(package_file),
            "--reviewer",
            "reviewerB",
            "--decision",
            "reject",
            "--reason",
            "still not enough",
        ]
    )
    captured = capsys.readouterr()

    assert second_exit == 0
    assert "GHI ĐÈ" in captured.err
    assert "reviewerA" in captured.err


def test_cli_mark_stale_excludes_target_from_both_read_paths(capsys, tmp_path):
    from context_store.store import SecurityContextStore

    context_db = str(tmp_path / "context.db")
    store = SecurityContextStore(db_path=context_db)
    store.record_unverified_observation("tgt_1", "exec_1", "some observation")
    store.promote_execution_to_verified("exec_1", "pkg_1")
    store.close()

    exit_code = cli.main(
        [
            "mark-stale",
            "--target-id",
            "tgt_1",
            "--reason",
            "revision changed, scope of impact unclear",
            "--context-db",
            context_db,
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "1" in captured.out

    store = SecurityContextStore(db_path=context_db)
    assert store.get_verified_context("tgt_1") == []
    store.close()


def test_cli_mark_stale_fails_cleanly_when_context_db_cannot_open(capsys, tmp_path):
    blocking_file = tmp_path / "not_a_dir"
    blocking_file.write_text("i am a file")
    context_db = str(blocking_file / "context.db")

    exit_code = cli.main(
        ["mark-stale", "--target-id", "tgt_1", "--reason", "x", "--context-db", context_db]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error" in captured.err


def test_full_pipeline_writes_unverified_then_promotes_to_verified_on_release(capsys, monkeypatch, tmp_path):
    # End-to-end SPEC §4.6 write path: execute() captures a real observation
    # -> Context Store holds it as unverified only -> review-package
    # --decision release promotes it -> get_verified_context() finally
    # returns it, ready to feed a future hypothesize() call for this
    # target_id.
    from context_store.store import SecurityContextStore

    execution_id = "exec_full_ctx_pipeline"
    context_db = str(tmp_path / "test.db")

    package_file = _assemble_a_real_package(capsys, monkeypatch, tmp_path, execution_id=execution_id)

    # After execute() but before any review: unverified only.
    store = SecurityContextStore(db_path=context_db)
    assert store.get_verified_context("tgt_test") == []
    unverified = store.get_unverified_context("tgt_test")
    assert len(unverified) == 1
    assert "CHƯA XÁC MINH" in unverified[0]["warning"]
    store.close()

    exit_code = cli.main(
        [
            "review-package",
            "--package-file",
            str(package_file),
            "--reviewer",
            "phuc@ntq.local",
            "--decision",
            "release",
            "--reason",
            "Cross-checked the raw evidence, matches the normalized observation.",
            "--checked-raw-artifact",
            "--context-db",
            context_db,
        ]
    )
    assert exit_code == 0

    # After release: promoted to verified, no longer unverified.
    store = SecurityContextStore(db_path=context_db)
    assert store.get_unverified_context("tgt_test") == []
    verified = store.get_verified_context("tgt_test")
    assert len(verified) == 1
    store.close()
