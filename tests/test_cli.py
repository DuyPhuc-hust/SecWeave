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
