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
        responses = [
            {
                "verifiable": True,
                "expected_behavior": "a",
                "suspected_behavior": "b",
                "observation_criteria": "c",
            }
            for _ in range(12)
        ]
        responses.append({"verifiable": False, "reason": "not enough context"})
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
