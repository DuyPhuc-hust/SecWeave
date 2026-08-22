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


def test_cli_hypothesize_target_id_without_revision_fails_cleanly(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review (revision-staleness fix,
    # 2026-08-19): --target-id alone used to be enough to query Context
    # Store — but a verified/unverified fact is only trustworthy for the
    # EXACT revision it was captured against (SecurityContextStore.
    # get_verified_context/get_unverified_context now require it). Without
    # --target-revision-id there's no way to filter correctly, so this
    # must fail cleanly rather than silently querying with an unknown
    # revision.
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
            "--target-id",
            "tgt_1",
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--target-revision-id" in captured.err


def test_cli_hypothesize_with_target_id_and_revision_queries_context_store_successfully(
    capsys, monkeypatch, tmp_path
):
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
            "--target-id",
            "tgt_1",
            "--target-revision-id",
            "rev_1",
            "--format",
            "json",
            "--context-db",
            str(tmp_path / "test.db"),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)[0]["result"]["status"] == "hypothesis"


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


# ----- Hypothesis-level revision tracking (2026-08-19): `plan` warns (but
# doesn't block) when acting on a hypothesis recorded for a different
# target_id/revision. -----


def _create_stored_hypothesis_for_target(capsys, monkeypatch, db_path: str, target_id: str, revision: str) -> str:
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

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
            "--target-id",
            target_id,
            "--target-revision-id",
            revision,
            "--format",
            "json",
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0
    return json.loads(capsys.readouterr().out)[0]["result"]["hypothesis"]["hypothesis_id"]


def test_cli_plan_warns_when_revision_differs_from_when_hypothesis_was_generated(
    capsys, monkeypatch, tmp_path
):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis_for_target(capsys, monkeypatch, db_path, "tgt_1", "rev_OLD")

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)
    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--target-id",
            "tgt_1",
            "--target-revision-id",
            "rev_NEW",
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0  # a warning, not a block — plan still proceeds normally
    assert "được sinh khi target ở revision" in captured.err
    assert "rev_OLD" in captured.err
    assert "rev_NEW" in captured.err


def test_cli_plan_warns_when_target_id_differs_from_when_hypothesis_was_generated(
    capsys, monkeypatch, tmp_path
):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis_for_target(capsys, monkeypatch, db_path, "tgt_OLD", "rev_1")

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)
    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--target-id",
            "tgt_NEW",
            "--target-revision-id",
            "rev_1",
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "được sinh cho target_id" in captured.err
    assert "tgt_OLD" in captured.err
    assert "tgt_NEW" in captured.err


def test_cli_plan_no_warning_when_revision_matches(capsys, monkeypatch, tmp_path):
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis_for_target(capsys, monkeypatch, db_path, "tgt_1", "rev_1")

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)
    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--target-id",
            "tgt_1",
            "--target-revision-id",
            "rev_1",
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "được sinh cho target_id" not in captured.err
    assert "được sinh khi target ở revision" not in captured.err


def test_cli_plan_no_warning_when_target_id_not_passed_at_all(capsys, monkeypatch, tmp_path):
    # Backward compatibility: --target-id/--target-revision-id are BOTH
    # optional on `plan` — a plan run without either must behave exactly
    # as before this feature existed, no warning, no crash.
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

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
    assert "được sinh cho target_id" not in captured.err
    assert "được sinh khi target ở revision" not in captured.err


def test_cli_plan_target_id_mismatch_wins_over_revision_mismatch_when_both_differ(
    capsys, monkeypatch, tmp_path
):
    # Real gap found via independent review: no test previously exercised
    # BOTH target_id AND revision differing at once (the realistic case —
    # a hypothesis for a genuinely different target naturally has an
    # unrelated revision too) — the target_id-mismatch warning (the more
    # informative one: "results may no longer be relevant AT ALL") must be
    # the one that fires, not the revision one.
    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis_for_target(capsys, monkeypatch, db_path, "tgt_OLD", "rev_OLD")

    monkeypatch.setattr(llm_module, "OpenAICompatibleLLMClient", _StubPlanLLMClient)
    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--target-id",
            "tgt_NEW",
            "--target-revision-id",
            "rev_NEW",
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "được sinh cho target_id" in captured.err
    assert "được sinh khi target ở revision" not in captured.err


def test_cli_plan_rejects_an_empty_target_id_for_the_staleness_check(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: unlike `execute` (which
    # rejects an empty --target-revision-id from an earlier review round),
    # `plan`'s --target-id/--target-revision-id had no such guard — an
    # empty string is just as falsy as None in the comparison, so it used
    # to silently disable the staleness check instead of erroring, making
    # a scripting mistake (an unset shell variable) indistinguishable from
    # "the operator didn't ask for this check."
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--target-id",
            "",
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "target_id" in captured.err
    assert "chuỗi rỗng" in captured.err


def test_cli_plan_rejects_an_empty_target_revision_id_for_the_staleness_check(capsys, monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    exit_code = cli.main(
        [
            "plan",
            "--hypothesis-id",
            hypothesis_id,
            "--target-revision-id",
            "",
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "revision" in captured.err
    assert "chuỗi rỗng" in captured.err


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


def test_cli_execute_rejects_an_empty_target_revision_id(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review (revision-staleness fix,
    # 2026-08-19): argparse's required=True on --target-revision-id only
    # checks the FLAG was passed, not that its VALUE is non-empty —
    # "--target-revision-id ''" used to sail through argparse, then crash
    # with an unhandled ValueError from Context Store's own
    # _require_revision the moment the first action's capture() tried to
    # write it (not caught by capture()'s best-effort
    # `except RuntimeError: pass`). Must fail cleanly, before any real
    # HTTP request, not with a raw traceback mid-run.
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

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
            "",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--target-revision-id" in captured.err
    assert "Traceback" not in captured.err


def test_cli_execute_rejects_an_empty_target_id(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review (whole-project audit,
    # 2026-08-19): --target-revision-id got this exact emptiness check
    # (above), but --target-id never did — the only place that happened to
    # reject "" was `_load_hypothesis_from_context_store`'s own staleness
    # cross-check, which only runs on the non---plan-file branch. The
    # documented, RECOMMENDED --plan-file path silently accepted
    # --target-id "" and baked it into every observation/Context Store
    # write for the run. Checked uniformly now, regardless of branch.
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

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
            "",
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
    assert "--target-id" in captured.err
    assert "Traceback" not in captured.err


def test_cli_kill_rejects_an_empty_execution_id(capsys, tmp_path):
    # Real gap found via independent review: `Path(storage_dir) / ""`
    # evaluates to storage_dir itself — an empty --execution-id silently
    # pointed KillSwitch at the storage_dir ROOT instead of erroring on the
    # obviously-mistyped flag.
    exit_code = cli.main(
        [
            "kill",
            "--execution-id",
            "",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--source",
            "operator",
            "--reason",
            "test",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--execution-id" in captured.err


def test_cli_resume_rejects_an_empty_execution_id(capsys, tmp_path):
    exit_code = cli.main(
        [
            "resume",
            "--execution-id",
            "",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--authorization-reference",
            "test",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--execution-id" in captured.err


def test_cli_resume_fails_cleanly_when_the_audit_log_write_fails(capsys, tmp_path):
    # Same shape as the analogous kill.py fix: resume()'s own audit-log
    # write can fail (disk full, permission loss — forced here via a
    # read-only file) AFTER this instance's in-memory status already
    # flipped, surfacing as a RuntimeError that `_run_resume` used to only
    # let escape uncaught (only ValueError was caught).
    import os
    import stat

    from shared.kill_switch import KillSwitch, StopSource

    storage_dir = str(tmp_path / "evidence")
    execution_id = "exec_resume_write_fails"
    kill_switch = KillSwitch(execution_id=execution_id, storage_dir=storage_dir)
    kill_switch.start()
    kill_switch.stop(source=StopSource.OPERATOR, reason="setup for test")

    audit_log_path = kill_switch._audit_log_path
    os.chmod(audit_log_path, stat.S_IREAD)
    try:
        exit_code = cli.main(
            [
                "resume",
                "--execution-id",
                execution_id,
                "--storage-dir",
                storage_dir,
                "--authorization-reference",
                "test",
            ]
        )
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "Traceback" not in captured.err
        assert "error:" in captured.err
    finally:
        os.chmod(audit_log_path, stat.S_IREAD | stat.S_IWRITE)


def test_cli_assemble_package_rejects_an_empty_execution_id(capsys, tmp_path):
    exit_code = cli.main(
        [
            "assemble-package",
            "--execution-id",
            "",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--target-id",
            "tgt_1",
            "--target-revision-id",
            "rev_1",
            "--environment",
            "sandbox",
            "--authorization-reference",
            "a",
            "--scenario",
            "s",
            "--limitations",
            "l",
            "--next-action",
            "n",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--execution-id" in captured.err


def test_cli_review_package_fails_cleanly_when_package_top_level_is_not_an_object(capsys, tmp_path):
    # Real gap found via independent review: `report`/`measure` (which read
    # the exact same VerificationPackage JSON artifact) both guard against
    # a wrong-shaped-but-valid-JSON top level — this command never got the
    # same guard, so `package_data.get(...)` raised a raw AttributeError.
    package_file = tmp_path / "bad.json"
    package_file.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    exit_code = cli.main(
        [
            "review-package",
            "--package-file",
            str(package_file),
            "--reviewer",
            "qa1",
            "--decision",
            "reject",
            "--reason",
            "x",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "JSON object" in captured.err


def _real_execute_artifacts(capsys, monkeypatch, tmp_path, execution_id: str, storage_dir):
    """Runs a real (mock-transport) `execute` and returns the execution
    directory holding its real observations.jsonl/actions.json/
    execution_status.json — shared setup for the malformed-artifact tests
    below, which corrupt one of these 3 files afterward."""
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)
    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))
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
    return Path(storage_dir) / execution_id


def test_cli_assemble_package_fails_cleanly_when_actions_json_top_level_is_not_a_list(
    capsys, monkeypatch, tmp_path
):
    # Real gap found via independent review: this parsing went straight
    # from json.loads() into ActionSpec(**item) with no shape check — a
    # hand-edited actions.json (an operator-editable file by design, see
    # `review-package`'s own docstring on this exact risk) whose top level
    # is a dict instead of a list crashed with a raw TypeError.
    storage_dir = tmp_path / "evidence"
    execution_dir = _real_execute_artifacts(capsys, monkeypatch, tmp_path, "exec_bad_actions_shape", storage_dir)
    (execution_dir / "actions.json").write_text(json.dumps({"not": "a list"}), encoding="utf-8")

    exit_code = cli.main(
        [
            "assemble-package",
            "--execution-id",
            "exec_bad_actions_shape",
            "--storage-dir",
            str(storage_dir),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--environment",
            "sandbox",
            "--authorization-reference",
            "a",
            "--scenario",
            "s",
            "--limitations",
            "l",
            "--next-action",
            "n",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "bị sửa tay" in captured.err


def test_cli_assemble_package_fails_cleanly_when_an_observation_line_is_not_an_object(
    capsys, monkeypatch, tmp_path
):
    storage_dir = tmp_path / "evidence"
    execution_dir = _real_execute_artifacts(capsys, monkeypatch, tmp_path, "exec_bad_obs_shape", storage_dir)
    (execution_dir / "observations.jsonl").write_text('"just a string"\n', encoding="utf-8")

    exit_code = cli.main(
        [
            "assemble-package",
            "--execution-id",
            "exec_bad_obs_shape",
            "--storage-dir",
            str(storage_dir),
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--environment",
            "sandbox",
            "--authorization-reference",
            "a",
            "--scenario",
            "s",
            "--limitations",
            "l",
            "--next-action",
            "n",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "bị sửa tay" in captured.err


def test_cli_execute_persist_actions_fails_cleanly_when_existing_actions_json_is_malformed(
    capsys, monkeypatch, tmp_path
):
    # Real gap found via independent review: actions.json is operator-
    # editable between 2 `execute` calls reusing the same execution_id (a
    # supported pattern) — an accidental hand-edit that breaks its
    # list-of-objects shape crashed `item["action_id"]` with a raw
    # TypeError/KeyError instead of a clean CliError.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)
    storage_dir = tmp_path / "evidence"
    execution_id = "exec_reused_bad_actions"
    execution_dir = storage_dir / execution_id
    execution_dir.mkdir(parents=True)
    (execution_dir / "actions.json").write_text(json.dumps({"not": "a list"}), encoding="utf-8")

    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))

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
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "bị sửa tay" in captured.err


def test_cli_identity_logins_rejects_a_non_object_entry(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: only the OUTER shape (dict)
    # was checked — a value that isn't itself a JSON object reached
    # `_IdentityLoginSpec(**cfg)` unguarded, raising a raw TypeError.
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _multi_identity_plan_file(tmp_path, hypothesis_id)

    logins_file = tmp_path / "bad_logins.json"
    logins_file.write_text(json.dumps({"owner": "typo'd string, not an object"}), encoding="utf-8")

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
    assert "Traceback" not in captured.err
    assert "phải là 1 JSON object" in captured.err


def test_cli_execute_fails_cleanly_when_execution_status_write_fails(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: unguarded, unlike `report`
    # --out's write — a disk-full/permission failure here happens AFTER
    # every real HTTP request of the run already completed, so a raw
    # traceback would also swallow the verdict printout.
    import httpx
    from pathlib import Path as _Path

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)
    storage_dir = tmp_path / "evidence"

    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))

    real_write_text = _Path.write_text

    def _broken_write_text(self, *args, **kwargs):
        if self.name == "execution_status.json":
            raise OSError("simulated disk failure")
        return real_write_text(self, *args, **kwargs)

    monkeypatch.setattr(_Path, "write_text", _broken_write_text)

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
            "exec_status_write_fails",
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "execution_status.json" in captured.err


def test_cli_execute_without_plan_file_warns_when_revision_differs(capsys, monkeypatch, tmp_path):
    # Same _load_hypothesis_from_context_store warning already tested for
    # `plan` — this confirms `execute`'s OWN non---plan-file branch (its
    # separate call site) actually passes args.target_id/
    # args.target_revision_id through too, not just that the shared
    # function works in isolation.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis_for_target(capsys, monkeypatch, db_path, "tgt_1", "rev_OLD")

    import hypothesis_engine.llm_client.openai_compatible_client as llm_module

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
            "tgt_1",
            "--target-revision-id",
            "rev_NEW",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0  # a warning, not a block
    assert "được sinh khi target ở revision" in captured.err
    assert "rev_OLD" in captured.err
    assert "rev_NEW" in captured.err


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


def test_cli_kill_fails_cleanly_when_the_audit_log_write_fails(capsys, tmp_path):
    # stop()'s own audit-log write can fail (disk full, permission loss,
    # or — as forced here — the log path unexpectedly being a directory)
    # AFTER this instance's in-memory status already flipped — surfaces as
    # a RuntimeError from KillSwitch.stop(), which `_run_kill` used to only
    # catch ValueError around, letting it crash uncaught instead of the
    # command's own error/exit-1 contract.
    storage_dir = str(tmp_path / "evidence")
    execution_id = "exec_kill_write_fails"
    execution_dir = tmp_path / "evidence" / execution_id
    execution_dir.mkdir(parents=True)
    (execution_dir / "kill_switch_audit_log.jsonl").mkdir()

    exit_code = cli.main(
        [
            "kill",
            "--execution-id",
            execution_id,
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
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "error:" in captured.err


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


def test_cli_execute_with_plan_file_warns_when_revision_differs(capsys, monkeypatch, tmp_path):
    # test_cli_execute_without_plan_file_warns_when_revision_differs already
    # covers the non---plan-file branch; this confirms the documented,
    # RECOMMENDED --plan-file path (which never reconstructs a Hypothesis
    # from Context Store, only replays the frozen ActionPlan) gets the
    # SAME staleness warning via _warn_if_hypothesis_stale, instead of
    # silently skipping it.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis_for_target(capsys, monkeypatch, db_path, "tgt_1", "rev_OLD")
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

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
            "tgt_1",
            "--target-revision-id",
            "rev_NEW",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0  # a warning, not a block
    assert "được sinh khi target ở revision" in captured.err
    assert "rev_OLD" in captured.err
    assert "rev_NEW" in captured.err


def test_cli_execute_with_plan_file_does_not_error_when_hypothesis_id_is_absent_from_context_db(
    capsys, monkeypatch, tmp_path
):
    # --plan-file has never required the hypothesis to still exist in
    # --context-db (a plan file can be handed off/replayed independently of
    # where it was originally generated) — the staleness check added above
    # must stay best-effort and not turn that into a new hard requirement.
    import httpx

    db_path = str(tmp_path / "test.db")  # never populated with any hypothesis
    hypothesis_id = "hyp_never_stored_anywhere"
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

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
            "tgt_1",
            "--target-revision-id",
            "rev_NEW",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "được sinh khi target ở revision" not in captured.err
    assert "được sinh cho target_id" not in captured.err
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


def test_cli_execute_establishes_session_from_a_dynamically_resolved_in_plan_login(
    capsys, monkeypatch, tmp_path
):
    # The generic, GENERIC-across-any-target scenario --identity-logins
    # can't express: a "victim" identity is only discovered by an EARLIER
    # action in THIS SAME plan (a {{FROM_STEP:...}}-chained registration,
    # server-assigned id/email unknown until runtime) — then a LATER
    # action's own response (a login using that dynamically-learned
    # email) establishes a session for its identity, which a STILL-LATER
    # action of the SAME identity automatically inherits with zero
    # --identity-logins entry. Also includes an UNRELATED role=setup
    # action (a plain marker-seed, nothing to do with this login) to
    # prove it does NOT get contaminated with the attacker's forged
    # session — real gap found by independent review: since identity used
    # to be resolved purely by role, and establishes_session forces
    # role=setup, any other role=setup action defaulted onto the exact
    # same identity/session with no warning. Uses a fully synthetic mock
    # API (not any real target's routes) specifically to prove this is a
    # general mechanism, not something that only works against one
    # target's shape.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_establishes_session_test"
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
                                "target": "http://mock.test/register",
                                "description": "Register a victim; server assigns email/id at runtime.",
                                "role": "setup",
                                "step_id": "register_victim",
                                "parameters": {"want": "victim"},
                            },
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://mock.test/login",
                                "description": "Attacker logs in using the dynamically-registered victim's email.",
                                "role": "setup",
                                "parameters": {"email": "{{FROM_STEP:register_victim:email}}", "password": "whatever"},
                                "establishes_session": {"for_role": "main", "token_json_path": "token"},
                            },
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://mock.test/seed-marker",
                                "description": "Unrelated setup action (e.g. a blind-marker seed) — must NOT inherit the attacker's forged session.",
                                "role": "setup",
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://mock.test/profile",
                                "description": "Uses the session established by the login action above — no --identity-logins entry for this identity at all.",
                                "role": "main",
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    FORGED_TOKEN = "forged-session-token-xyz"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/register":
            return httpx.Response(200, json={"id": 99, "email": "victim99@mock.test"})
        if request.url.path == "/login":
            body = json.loads(request.content)
            if body["email"] == "victim99@mock.test":
                return httpx.Response(200, json={"token": FORGED_TOKEN})
            return httpx.Response(401, json={"error": "invalid credentials"})
        if request.url.path == "/seed-marker":
            # The unrelated setup action, run by the DEFAULT identity
            # ("anonymous", no --role-identity setup=... override) — must
            # arrive with no Authorization header at all.
            if "Authorization" in request.headers:
                return httpx.Response(500, json={"error": "CONTAMINATED: unexpected Authorization header"})
            return httpx.Response(200, json={"ok": True})
        if request.url.path == "/profile":
            auth = request.headers.get("Authorization")
            if auth == f"Bearer {FORGED_TOKEN}":
                return httpx.Response(200, json={"marker": "this-is-the-session-proof"})
            return httpx.Response(401, json={"error": "no session"})
        raise AssertionError(f"unexpected path: {request.url.path}")

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--role-identity",
            "main=attacker",
            "--allowed-action",
            "POST http://mock.test/register params:want",
            "--allowed-action",
            "POST http://mock.test/login params:email,password",
            "--allowed-action",
            "POST http://mock.test/seed-marker",
            "--allowed-action",
            "GET http://mock.test/profile",
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
    captured = capsys.readouterr()
    assert exit_code == 0, captured.err
    assert "Traceback" not in captured.err

    log_path = storage_dir / execution_id / "observations.jsonl"
    from shared.models.observation import NormalizedObservation

    observations = [NormalizedObservation(**json.loads(line)) for line in log_path.read_text().splitlines()]
    by_role = [(o.role.value, o.identity, o.access_result.value, o.status_code) for o in observations]
    assert by_role == [
        ("setup", "anonymous", "granted", 200),  # register_victim (default identity, no --role-identity setup=... override)
        ("setup", "attacker", "granted", 200),  # establishes_session login, for_role=main resolves via --role-identity main=attacker
        ("setup", "anonymous", "granted", 200),  # unrelated setup action — did NOT inherit the attacker's session (200, not 500)
        ("main", "attacker", "granted", 200),  # profile read, using the inherited session
    ]


def test_cli_execute_from_step_referencing_the_establishes_session_token_path_fails_cleanly(
    capsys, monkeypatch, tmp_path
):
    # Real gap found by independent review: harness.login() rewrites the
    # just-written artifact's response body, redacting the value at its
    # own token_json_path, BEFORE cli/commands/execute.py's
    # _load_step_response_body() reads that same artifact to populate
    # step_responses. A later action FROM_STEP-referencing that EXACT
    # path used to silently receive the literal "<redacted>" placeholder
    # text instead of the real token — must now fail cleanly instead.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_from_step_redacted_token_test"
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
                                "target": "http://mock.test/login",
                                "description": "Establishes a session; also tagged with a step_id.",
                                "role": "setup",
                                "step_id": "do_login",
                                "parameters": {"email": "attacker@mock.test", "password": "whatever"},
                                "establishes_session": {"for_role": "main", "token_json_path": "token"},
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://mock.test/echo",
                                "description": "Tries to re-extract the already-redacted token via FROM_STEP.",
                                "role": "main",
                                "parameters": {"leaked": "{{FROM_STEP:do_login:token}}"},
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, json={"token": "real-secret-token-abc"})
        raise AssertionError(f"unexpected path reached: {request.url.path} — should have failed before this")

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "execute",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--allowed-action",
            "POST http://mock.test/login params:email,password",
            "--allowed-action",
            "GET http://mock.test/echo params:leaked",
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
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "redact" in captured.err.lower()


def test_cli_execute_login_token_extraction_failure_still_persists_the_observation(
    capsys, monkeypatch, tmp_path
):
    # The login request itself already went through capture() before
    # token extraction failed — a real cost slot was consumed and a real
    # evidence artifact was written to disk. Losing that observation (no
    # observations.jsonl entry ever pointing at it) would silently orphan
    # already-consumed cost/evidence with zero trace in the one file every
    # downstream command (assemble-package/retest/measure) actually reads.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_login_orphan_test"
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
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 1

    log_path = storage_dir / execution_id / "observations.jsonl"
    from shared.models.observation import NormalizedObservation

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    observation = NormalizedObservation(**json.loads(lines[0]))
    assert observation.role.value == "setup"
    assert observation.identity == "owner"
    # The real HTTP response (200) was already received before extraction
    # failed — access_result reflects that real outcome, not the later
    # extraction failure.
    assert observation.access_result.value == "granted"

    # The stored artifact's hash/size must match the REDACTED body actually
    # on disk (post-failure, the whole body gets wiped — see login()'s own
    # docstring), not a stale pre-redaction hash from before the rewrite.
    artifact = json.loads(Path(observation.raw_evidence_ref).read_text(encoding="utf-8"))
    assert "redact" in artifact["response"]["body"]
    actual_bytes = Path(observation.raw_evidence_ref).read_bytes()
    import hashlib

    assert observation.raw_evidence_hash == "sha256:" + hashlib.sha256(actual_bytes).hexdigest()
    assert observation.raw_evidence_size_bytes == len(actual_bytes)


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


def test_cli_execute_from_step_fails_cleanly_when_the_source_artifact_cannot_be_reread(
    capsys, monkeypatch, tmp_path
):
    # The step_id action's own response was already captured successfully
    # (real cost/evidence recorded) before a LATER action's {{FROM_STEP:...}}
    # reference tries to read that artifact back. If the artifact can't be
    # re-read (removed by a concurrent process, a transient disk error) this
    # used to escape as a raw, uncaught FileNotFoundError instead of the
    # command's own error/exit-1 contract — the same "narrow except clause
    # misses a real failure mode" class of bug this project has hit and
    # fixed many times before.
    import httpx

    import evidence_harness.harness as harness_module

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_from_step_unreadable_artifact"
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

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/notes":
            return httpx.Response(200, json={"id": 42})
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    real_capture = harness_module.EvidenceHarness.capture

    def capture_then_delete_seed_note_artifact(self, action, *args, **kwargs):
        observation = real_capture(self, action, *args, **kwargs)
        if action.target == "http://host.docker.internal:3000/notes":
            Path(observation.raw_evidence_ref).unlink()
        return observation

    monkeypatch.setattr(harness_module.EvidenceHarness, "capture", capture_then_delete_seed_note_artifact)

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
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "seed_note" in captured.err or "step_id" in captured.err


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


def test_cli_assemble_package_writes_a_package_manifest_covering_every_run_artifact(capsys, monkeypatch, tmp_path):
    # SPEC §4.3.3: "package chứa manifest liệt kê hash → phát hiện thay đổi
    # ngoài ý muốn." Confirms assemble-package actually writes this
    # manifest as a side effect, that it lists every real artifact
    # execute() persisted (not just the ones VerificationPackage's own
    # field #10/#11 already cover), and that running assemble-package a
    # SECOND time for the same execution doesn't fold a stale copy of the
    # manifest's own prior output back into itself.
    import hashlib

    import httpx

    from verification_package.manifest import PACKAGE_MANIFEST_FILENAME, ArtifactManifest

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_manifest_test"
    storage_dir = tmp_path / "evidence"
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

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
    capsys.readouterr()

    assemble_args = [
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
        "s",
        "--limitations",
        "l",
        "--next-action",
        "n",
        "--format",
        "json",
    ]

    exit_code = cli.main(assemble_args)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "package manifest" in captured.err

    execution_dir = storage_dir / execution_id
    manifest_path = execution_dir / PACKAGE_MANIFEST_FILENAME
    assert manifest_path.exists()
    manifest = ArtifactManifest(**json.loads(manifest_path.read_text(encoding="utf-8")))
    assert manifest.execution_id == execution_id
    manifest_filenames = {e.filename for e in manifest.entries}
    assert {"actions.json", "observations.jsonl", "execution_status.json"}.issubset(manifest_filenames)
    assert PACKAGE_MANIFEST_FILENAME not in manifest_filenames

    # Cross-check one real hash against the actual on-disk bytes.
    actions_entry = next(e for e in manifest.entries if e.filename == "actions.json")
    real_bytes = (execution_dir / "actions.json").read_bytes()
    assert actions_entry.sha256_hash == "sha256:" + hashlib.sha256(real_bytes).hexdigest()
    assert actions_entry.size_bytes == len(real_bytes)

    # Re-running assemble-package must not fold the manifest's own prior
    # output back into itself as a phantom entry.
    exit_code_again = cli.main(assemble_args)
    capsys.readouterr()
    assert exit_code_again == 0
    manifest_again = ArtifactManifest(**json.loads(manifest_path.read_text(encoding="utf-8")))
    assert {e.filename for e in manifest_again.entries} == manifest_filenames


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
    assert store.get_unverified_context("tgt_test", "rev_test") == []
    verified = store.get_verified_context("tgt_test", "rev_test")
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


def test_cli_review_package_rejects_retest_reference_with_reject_decision(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review (original version of this
    # check): --retest-reference could be attached to ANY decision at all,
    # including reject — pointless, and a realistic copy-paste mistake to
    # guard against. NOTE: release is deliberately NOT rejected here (see
    # test_cli_review_package_accepts_retest_reference_with_release_decision
    # right below) — a SECOND real gap found running this pipeline for real
    # (2026-08-20): the ORIGINAL fix for this incident only allowed
    # --decision retest, which made retest_reference permanently
    # unattachable for the one decision that actually needs it for
    # is_release_ready (SPEC §8.1's reproducibility gate applies to every
    # release, not just a decision=retest one).
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
            "test",
            "--retest-reference",
            "retest_123",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "retest" in captured.err


def test_cli_review_package_accepts_retest_reference_with_release_decision(capsys, monkeypatch, tmp_path):
    # Real gap found running this pipeline for real (2026-08-20): a package
    # that had `secweave retest` run separately, then genuinely reviewed
    # and released, could never have --retest-reference attached at all —
    # the original fix for the sibling test above only permitted
    # --decision retest, leaving is_release_ready permanently False (missing
    # retest_reference) for every real released package.
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
            "--format",
            "json",
        ]
    )
    reviewed_output = capsys.readouterr().out
    reviewed = json.loads(reviewed_output)

    assert exit_code == 0
    assert reviewed["retest_reference"] == "retest_123"

    # Confirm via the REAL is_release_ready gate (measure), not just that
    # the field round-tripped — this is what actually stayed broken before
    # this fix (retest_reference present has no effect if the CLI never
    # let it coexist with decision=release in the first place).
    package_file.write_text(reviewed_output, encoding="utf-8")
    measure_exit_code = cli.main(["measure", "--package-file", str(package_file), "--format", "json"])
    measure_report = json.loads(capsys.readouterr().out)
    assert measure_exit_code == 0
    assert measure_report["schema_completeness"] == {"is_release_ready": True, "missing_fields": []}


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
    store.record_unverified_observation("tgt_1", "exec_1", "some observation", "rev_1")
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
    assert store.get_verified_context("tgt_1", "rev_1") == []
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
    assert store.get_verified_context("tgt_test", "rev_test") == []
    unverified = store.get_unverified_context("tgt_test", "rev_test")
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
    assert store.get_unverified_context("tgt_test", "rev_test") == []
    verified = store.get_verified_context("tgt_test", "rev_test")
    assert len(verified) == 1
    store.close()


# ----- `secweave retest`: reproducibility (SPEC §8.1, WEEKLY_PLAN W7) (2026-08-19) -----


def _single_role_plan_file(tmp_path, hypothesis_id: str) -> Path:
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
                                "description": "Ordinary single-role read.",
                            }
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return plan_file


def test_cli_retest_requires_a_plan_file(capsys, monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)

    exit_code = cli.main(
        [
            "retest",
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
    assert exit_code == 1
    assert "--plan-file" in captured.err


def test_cli_retest_requires_at_least_2_runs(capsys, monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

    exit_code = cli.main(
        [
            "retest",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--runs",
            "1",
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
    assert exit_code == 1
    assert "--runs" in captured.err


def test_cli_retest_runs_n_independent_times_and_reports_full_agreement(capsys, monkeypatch, tmp_path):
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)
    storage_dir = tmp_path / "evidence"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "retest",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--runs",
            "3",
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            "exec_retest_base",
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0

    # A single-role plan (no controls) always resolves to inconclusive —
    # deterministic across all 3 independent runs.
    summary_path = storage_dir / "exec_retest_base_retest_summary.json"
    summary = json.loads(summary_path.read_text())
    assert summary["runs"] == 3
    assert [r["verdict"] for r in summary["results"]] == ["inconclusive"] * 3
    assert summary["most_common_verdict"] == "inconclusive"
    assert summary["agreement_count"] == 3
    assert summary["agreement_ratio"] == 1.0
    assert summary["meets_recommended_threshold"] is True
    assert summary["retest_id"] in captured.out  # --format json prints it too

    # Each run got its OWN independent execution — 3 separate evidence dirs.
    for i in (1, 2, 3):
        assert (storage_dir / f"exec_retest_base_retest{i}" / "observations.jsonl").exists()


def test_cli_retest_reports_disagreement_when_verdicts_actually_differ(capsys, monkeypatch, tmp_path):
    # A real, deterministic way to exercise the "verdicts differ across
    # runs" path: a full 3-role + blind-marker plan (same shape as
    # test_cli_execute_substitutes_blind_marker_and_satisfies_the_main_predicate,
    # which reaches a real CONFIRMED) where the denied_control action's
    # behavior changes after the first 2 total captures across the whole
    # retest (simulating a flaky/inconsistent real target): runs 1-2 see a
    # false-granted denied control (main+positive still satisfied, but
    # oracle.py's denied-check short-circuits before ever reaching main ->
    # NOT_REPRODUCED); run 3 sees denied_control correctly denied, so all
    # 3 groups are satisfied -> CONFIRMED. 2/3 agreement, not 3/3.
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
                            {
                                "type": "test_data_creation",
                                "method": "POST",
                                "target": "http://host.docker.internal:3000/notes",
                                "description": "Seed a note with a blind marker.",
                                "role": "setup",
                                "parameters": {"content": "{{SECWEAVE_BLIND_MARKER}}"},
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/notes/1",
                                "description": "Positive control.",
                                "role": "positive_control",
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/notes/1",
                                "description": "Denied control.",
                                "role": "denied_control",
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/notes/1",
                                "description": "Main: read the seeded note back.",
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
    get_call_count = [0]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/notes":
            body = json.loads(request.content)
            seeded_content.append(body["content"])
            return httpx.Response(200, json={"id": 1})
        # Each run makes exactly 3 GET /notes/1 calls, in plan order:
        # positive_control, denied_control, main. Position 1 (0-indexed)
        # within each run's 3 calls is always denied_control. Deliberately
        # makes RUN 1 the MINORITY outcome (confirmed) and runs 2-3 the
        # MAJORITY (not_reproduced) — real gap found via independent
        # review: an earlier version made run 1 agree with the majority,
        # so a broken implementation that took results[0]'s verdict as
        # "most common" instead of the true majority would have produced
        # the exact same (wrong-for-the-wrong-reason) assertions. Ordering
        # the minority outcome FIRST forces the test to actually exercise
        # majority-counting logic, not first-result logic.
        get_call_count[0] += 1
        position_in_run = (get_call_count[0] - 1) % 3
        run_index = (get_call_count[0] - 1) // 3  # 0, 1, 2 for run 1, 2, 3
        if position_in_run == 1:  # denied_control
            if run_index == 0:
                return httpx.Response(403, json={})  # correctly denied, only on run 1
            return httpx.Response(200, json={"content": seeded_content[-1]})  # incorrectly granted
        return httpx.Response(200, json={"content": seeded_content[-1]})

    _patch_evidence_harness_transport(monkeypatch, handler)

    exit_code = cli.main(
        [
            "retest",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--runs",
            "3",
            "--allowed-action",
            "POST http://host.docker.internal:3000/notes params:content",
            "--allowed-action",
            "GET http://host.docker.internal:3000/notes/1",
            "--role-identity",
            "positive_control=owner",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            "exec_retest_disagree",
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0

    summary = json.loads((storage_dir / "exec_retest_disagree_retest_summary.json").read_text())
    assert [r["verdict"] for r in summary["results"]] == ["confirmed", "not_reproduced", "not_reproduced"]
    assert summary["most_common_verdict"] == "not_reproduced"
    assert summary["agreement_count"] == 2
    assert summary["agreement_ratio"] == pytest.approx(2 / 3)
    assert summary["meets_recommended_threshold"] is True  # 2/3 >= 2/3


def test_cli_retest_stops_immediately_on_a_setup_failure_instead_of_limping_through(
    capsys, monkeypatch, tmp_path
):
    # A config mistake (here: a malformed --identity-logins file) would hit
    # every one of the N runs identically — failing the whole batch on the
    # FIRST occurrence is more honest than silently reporting on however
    # many runs happened to complete first.
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

    logins_file = tmp_path / "bad_logins.json"
    logins_file.write_text("not valid json", encoding="utf-8")

    exit_code = cli.main(
        [
            "retest",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--runs",
            "3",
            "--identity-logins",
            str(logins_file),
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
    assert exit_code == 1
    assert "lần 1/3" in captured.err
    assert "Traceback" not in captured.err


def test_cli_retest_surfaces_runs_that_captured_no_verdict_at_all(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: agreement_ratio alone can't
    # tell a reader WHY it's below threshold — a run that never captured
    # anything (e.g. BLOCKED by the planning-time cost cap, same cap
    # applies identically to every run here) looks, at that one field,
    # indistinguishable from a run that genuinely produced a DIFFERENT
    # verdict. runs_with_no_verdict makes this explicit instead of making
    # a reader cross-reference `results` by hand.
    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

    exit_code = cli.main(
        [
            "retest",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--runs",
            "3",
            "--cap",
            "0",  # blocks every run identically at the planning-time cost check
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            "exec_retest_no_verdict",
            "--storage-dir",
            str(tmp_path / "evidence"),
            "--context-db",
            db_path,
        ]
    )
    assert exit_code == 0

    summary = json.loads((tmp_path / "evidence" / "exec_retest_no_verdict_retest_summary.json").read_text())
    assert [r["verdict"] for r in summary["results"]] == [None, None, None]
    assert summary["runs_with_no_verdict"] == 3
    assert summary["most_common_verdict"] is None
    assert summary["agreement_count"] == 0


def test_cli_retest_continues_past_one_runs_corrupted_artifact_instead_of_aborting_the_batch(
    capsys, monkeypatch, tmp_path
):
    # Real gap found via independent review: the retest loop's own call to
    # _read_verdict_for_execution used to be UNGUARDED, unlike
    # _run_execute()'s call right above it — a corrupted/torn
    # observations.jsonl line for just ONE run used to abort the WHOLE
    # batch (raising CliError all the way up), discarding the verdicts of
    # every run that already completed successfully, even though those
    # runs already sent real HTTP requests and consumed real cost-cap
    # budget. A per-run artifact corruption must only cost THAT run's
    # verdict, not the whole batch's results.
    import cli.commands.retest as retest_module
    import httpx
    from cli.common import CliError

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)
    storage_dir = tmp_path / "evidence"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _patch_evidence_harness_transport(monkeypatch, handler)

    real_read_verdict = retest_module._read_verdict_for_execution

    def _fake_read_verdict(execution_id, storage_dir_arg):
        if execution_id == "exec_retest_corrupt_retest2":
            raise CliError("giả lập observations.jsonl bị hỏng cho lần 2")
        return real_read_verdict(execution_id, storage_dir_arg)

    monkeypatch.setattr(retest_module, "_read_verdict_for_execution", _fake_read_verdict)

    exit_code = cli.main(
        [
            "retest",
            "--hypothesis-id",
            hypothesis_id,
            "--plan-file",
            str(plan_file),
            "--runs",
            "3",
            "--allowed-action",
            "GET http://host.docker.internal:3000",
            "--target-id",
            "tgt_test",
            "--target-revision-id",
            "rev_test",
            "--execution-id",
            "exec_retest_corrupt",
            "--storage-dir",
            str(storage_dir),
            "--context-db",
            db_path,
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 0  # must NOT abort the whole batch
    assert "không đọc được verdict" in captured.err

    summary = json.loads((storage_dir / "exec_retest_corrupt_retest_summary.json").read_text())
    assert summary["runs"] == 3
    assert summary["runs_with_corrupted_artifact"] == 1
    verdicts = [r["verdict"] for r in summary["results"]]
    assert verdicts.count("inconclusive") == 2  # runs 1 and 3 completed normally
    assert verdicts.count(None) == 1  # run 2's unreadable verdict recorded as None, not a crash


def test_cli_measure_requires_at_least_one_input(capsys):
    exit_code = cli.main(["measure"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "ít nhất 1" in captured.err


def test_cli_measure_reports_schema_completeness_from_a_real_package_and_updates_after_release(
    capsys, monkeypatch, tmp_path
):
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_measure_schema"
    storage_dir = tmp_path / "evidence"
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))

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

    package_file = tmp_path / "package.json"
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
                "auth_local_test_1",
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
    package_file.write_text(capsys.readouterr().out, encoding="utf-8")

    # Freshly assembled — missing human_review_record + retest_reference.
    exit_code = cli.main(["measure", "--package-file", str(package_file), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["schema_completeness"]["is_release_ready"] is False
    assert "human_review_record" in report["schema_completeness"]["missing_fields"]
    assert "retest_reference" in report["schema_completeness"]["missing_fields"]
    # ECS and "khả năng bàn giao" are always N/A, regardless of input.
    assert report["ecs"]["status"].startswith("N/A")
    assert report["khả_năng_bàn_giao"]["status"].startswith("N/A")

    # Release it for real (Gate 4 minimal loop), attaching a real
    # --retest-reference in the SAME step (supported alongside
    # decision=release — see
    # test_cli_review_package_accepts_retest_reference_with_release_decision
    # for the dedicated regression test of that fix), then re-measure the
    # SAME underlying execution — schema completeness must flip to ready.
    assert (
        cli.main(
            [
                "review-package",
                "--package-file",
                str(package_file),
                "--reviewer",
                "qa1",
                "--decision",
                "release",
                "--reason",
                "ok",
                "--checked-raw-artifact",
                "--retest-reference",
                "retest_dummy_1",
                "--context-db",
                db_path,
                "--format",
                "json",
            ]
        )
        == 0
    )
    package_file.write_text(capsys.readouterr().out, encoding="utf-8")

    exit_code = cli.main(["measure", "--package-file", str(package_file), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["schema_completeness"] == {"is_release_ready": True, "missing_fields": []}


def test_cli_measure_fails_cleanly_on_a_malformed_package_file(capsys, tmp_path):
    package_file = tmp_path / "bad.json"
    package_file.write_text("not json", encoding="utf-8")
    exit_code = cli.main(["measure", "--package-file", str(package_file)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "JSON hợp lệ" in captured.err


def test_cli_measure_reports_reproducibility_from_a_real_retest_run_and_cross_checks_raw_artifact(
    capsys, monkeypatch, tmp_path
):
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)
    storage_dir = tmp_path / "evidence"

    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))

    assert (
        cli.main(
            [
                "retest",
                "--hypothesis-id",
                hypothesis_id,
                "--plan-file",
                str(plan_file),
                "--runs",
                "2",
                "--allowed-action",
                "GET http://host.docker.internal:3000",
                "--target-id",
                "tgt_test",
                "--target-revision-id",
                "rev_test",
                "--execution-id",
                "exec_measure_retest",
                "--storage-dir",
                str(storage_dir),
                "--context-db",
                db_path,
            ]
        )
        == 0
    )
    capsys.readouterr()

    summary_path = storage_dir / "exec_measure_retest_retest_summary.json"
    exit_code = cli.main(
        [
            "measure",
            "--retest-summary",
            str(summary_path),
            "--storage-dir",
            str(storage_dir),
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 0
    assert report["reproducibility"]["cross_checked_against_raw_artifact"] == 2
    assert report["reproducibility"]["agreement_ratio"] == 1.0
    assert "WARNING_mismatch_with_raw_artifact" not in report["reproducibility"]
    assert "CẢNH BÁO" not in captured.err
    # control effectiveness untouched since --execution-id wasn't passed.
    assert report["control_effectiveness"]["status"].startswith("N/A")


def test_cli_measure_warns_on_a_tampered_retest_summary_without_hard_failing(capsys, monkeypatch, tmp_path):
    # measure is a REPORTING command, not a release gate (that's
    # review-package's job) — a mismatch between what the summary claims and
    # what the raw artifact actually says must be surfaced loudly, but must
    # NOT make the whole report unusable the way review-package's hard
    # rejection would for a promotion decision.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)
    storage_dir = tmp_path / "evidence"

    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))

    assert (
        cli.main(
            [
                "retest",
                "--hypothesis-id",
                hypothesis_id,
                "--plan-file",
                str(plan_file),
                "--runs",
                "2",
                "--allowed-action",
                "GET http://host.docker.internal:3000",
                "--target-id",
                "tgt_test",
                "--target-revision-id",
                "rev_test",
                "--execution-id",
                "exec_measure_tampered",
                "--storage-dir",
                str(storage_dir),
                "--context-db",
                db_path,
            ]
        )
        == 0
    )
    capsys.readouterr()

    summary_path = storage_dir / "exec_measure_tampered_retest_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["results"][0]["verdict"] = "confirmed"  # real verdict for a single GET, role=main run is inconclusive
    summary["agreement_count"] = 2
    summary["agreement_ratio"] = 1.0
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    exit_code = cli.main(
        [
            "measure",
            "--retest-summary",
            str(summary_path),
            "--storage-dir",
            str(storage_dir),
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 0  # a warning, not a hard failure
    assert len(report["reproducibility"]["WARNING_mismatch_with_raw_artifact"]) == 1
    assert report["reproducibility"]["WARNING_mismatch_with_raw_artifact"][0]["khai_trong_summary"] == "confirmed"
    assert report["reproducibility"]["WARNING_mismatch_with_raw_artifact"][0]["tinh_lai_tu_raw_artifact"] == "inconclusive"
    assert "CẢNH BÁO" in captured.err


def test_cli_measure_does_not_count_a_corrupted_artifact_as_cross_checked(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: `cross_checked` used to be
    # incremented BEFORE the try/except around _read_verdict_for_execution
    # — a run whose observations.jsonl EXISTS but is corrupted (unreadable)
    # still counted toward "N cross-checked", even though the comparison
    # against the declared verdict never actually happened. That silently
    # defeats the entire purpose of this cross-check: a hand-tampered
    # summary sitting next to a corrupted artifact would report "N/N
    # cross-checked, no mismatch" while having verified nothing for that
    # run.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)
    storage_dir = tmp_path / "evidence"

    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))

    assert (
        cli.main(
            [
                "retest",
                "--hypothesis-id",
                hypothesis_id,
                "--plan-file",
                str(plan_file),
                "--runs",
                "2",
                "--allowed-action",
                "GET http://host.docker.internal:3000",
                "--target-id",
                "tgt_test",
                "--target-revision-id",
                "rev_test",
                "--execution-id",
                "exec_measure_corrupt",
                "--storage-dir",
                str(storage_dir),
                "--context-db",
                db_path,
            ]
        )
        == 0
    )
    capsys.readouterr()

    # Corrupt run 1's observations.jsonl AFTER it already completed
    # successfully and consumed real cost-cap budget.
    corrupted_path = storage_dir / "exec_measure_corrupt_retest1" / "observations.jsonl"
    corrupted_path.write_text("not valid json\n", encoding="utf-8")

    summary_path = storage_dir / "exec_measure_corrupt_retest_summary.json"
    exit_code = cli.main(
        [
            "measure",
            "--retest-summary",
            str(summary_path),
            "--storage-dir",
            str(storage_dir),
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 0  # a warning, not a hard failure
    assert report["reproducibility"]["cross_checked_against_raw_artifact"] == 1  # only run 2, NOT run 1
    assert report["reproducibility"]["runs_with_corrupted_artifact"] == 1
    assert "WARNING_mismatch_with_raw_artifact" not in report["reproducibility"]  # nothing to compare, not a mismatch
    assert "CẢNH BÁO" in captured.err


def test_cli_measure_rejects_a_retest_summary_missing_required_fields(capsys, tmp_path):
    summary_path = tmp_path / "bad_summary.json"
    summary_path.write_text(json.dumps({"runs": 2}), encoding="utf-8")
    exit_code = cli.main(["measure", "--retest-summary", str(summary_path)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "thiếu field" in captured.err


def test_cli_measure_rejects_a_retest_summary_with_a_non_numeric_agreement_ratio(capsys, tmp_path):
    summary_path = tmp_path / "bad_summary.json"
    summary_path.write_text(
        json.dumps({"runs": 2, "agreement_ratio": "lots", "meets_recommended_threshold": True, "results": []}),
        encoding="utf-8",
    )
    exit_code = cli.main(["measure", "--retest-summary", str(summary_path)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "agreement_ratio phải là số" in captured.err


def test_cli_measure_reports_control_effectiveness_from_a_real_execute_run_and_flags_actions_outside_allowlist(
    capsys, monkeypatch, tmp_path
):
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_measure_control"
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
                                "target": "http://host.docker.internal:3000/",
                                "description": "in-scope read",
                            },
                            {
                                "type": "read_only",
                                "method": "GET",
                                "target": "http://host.docker.internal:3000/other",
                                "description": "NOT in the allowlist passed to `measure` below",
                            },
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))

    assert (
        cli.main(
            [
                "execute",
                "--hypothesis-id",
                hypothesis_id,
                "--plan-file",
                str(plan_file),
                "--allowed-action",
                "GET http://host.docker.internal:3000/",
                "--allowed-action",
                "GET http://host.docker.internal:3000/other",
                "--cap",
                "5",
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

    # Re-verify against a NARROWER allowlist than the one execute actually
    # used (simulating a later, stricter audit of what was allowed at the
    # time) — the 2nd action must show up as outside allowlist.
    exit_code = cli.main(
        [
            "measure",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--allowed-action",
            "GET http://host.docker.internal:3000/",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 0
    ce = report["control_effectiveness"]
    assert ce["total_actions"] == 2
    assert ce["actions_outside_allowlist_count"] == 1
    assert ce["actions_outside_allowlist"] == ["GET http://host.docker.internal:3000/other"]
    assert ce["cost"]["executed_action_count"] == 2
    assert ce["cost"]["cap"] == 5
    assert ce["kill_switch"]["automatic_threshold_stops"] == 0

    # Without --allowed-action at all, the allowlist check is reported as
    # not attempted (N/A), not silently 0 (which would look like "verified
    # clean" when nothing was actually checked).
    exit_code = cli.main(
        [
            "measure",
            "--execution-id",
            execution_id,
            "--storage-dir",
            str(storage_dir),
            "--format",
            "json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["control_effectiveness"]["actions_outside_allowlist_count"] == "N/A — không truyền --allowed-action"


def test_cli_measure_fails_cleanly_when_execution_id_was_never_run(capsys, tmp_path):
    exit_code = cli.main(
        [
            "measure",
            "--execution-id",
            "exec_never_ran",
            "--storage-dir",
            str(tmp_path / "evidence"),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "actions.json" in captured.err
    assert "Traceback" not in captured.err


def test_cli_measure_fails_cleanly_when_package_file_top_level_is_not_an_object(capsys, tmp_path):
    # Real gap found via independent review: valid JSON whose top level is a
    # list (not an object) crashed VerificationPackage(**package_data) with
    # a raw, uncaught TypeError ("argument after ** must be a mapping, not
    # list") instead of the command's own error/exit-1 contract — a
    # realistic mistake for a reporting tool pointed at an arbitrary file
    # (wrong file picked, hand-edited, truncated).
    package_file = tmp_path / "not_an_object.json"
    package_file.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    exit_code = cli.main(["measure", "--package-file", str(package_file)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "JSON object" in captured.err


def test_cli_measure_fails_cleanly_when_retest_summary_results_entries_are_not_objects(capsys, tmp_path):
    # Real gap found via independent review: "results" entries that parse as
    # valid JSON but aren't dicts (e.g. plain strings) crashed
    # entry.get("execution_id") with a raw, uncaught AttributeError instead
    # of failing cleanly.
    summary_path = tmp_path / "bad_results.json"
    summary_path.write_text(
        json.dumps(
            {"runs": 1, "agreement_ratio": 1.0, "meets_recommended_threshold": True, "results": ["oops"]}
        ),
        encoding="utf-8",
    )
    exit_code = cli.main(["measure", "--retest-summary", str(summary_path)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "results phải là" in captured.err


def test_cli_measure_fails_cleanly_when_actions_json_top_level_is_not_a_list(capsys, tmp_path):
    # Real gap found via independent review: an actions.json whose top level
    # is a dict (not a list) iterated over its string KEYS in the list
    # comprehension, crashing ActionSpec(**item) with a raw, uncaught
    # TypeError instead of failing cleanly.
    storage_dir = tmp_path / "evidence"
    execution_dir = storage_dir / "exec_bad_actions"
    execution_dir.mkdir(parents=True)
    (execution_dir / "actions.json").write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    exit_code = cli.main(
        ["measure", "--execution-id", "exec_bad_actions", "--storage-dir", str(storage_dir)]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "danh sách ActionSpec" in captured.err


def test_cli_measure_fails_cleanly_when_kill_switch_log_cannot_be_read(capsys, tmp_path):
    # kill_switch_audit_log.jsonl passing .exists() doesn't guarantee
    # .read_text() succeeds (permission change, transient disk error, or —
    # as forced here — the path unexpectedly being a directory). This used
    # to escape as a raw, uncaught OSError instead of the command's own
    # error/exit-1 contract, the same "narrow except clause misses a real
    # failure mode" class of bug this project has hit and fixed many times
    # (httpx.InvalidURL, a closed EvidenceHarness client's RuntimeError).
    storage_dir = tmp_path / "evidence"
    execution_dir = storage_dir / "exec_bad_kill_switch_log"
    execution_dir.mkdir(parents=True)
    (execution_dir / "actions.json").write_text("[]", encoding="utf-8")
    (execution_dir / "kill_switch_audit_log.jsonl").mkdir()
    exit_code = cli.main(
        ["measure", "--execution-id", "exec_bad_kill_switch_log", "--storage-dir", str(storage_dir)]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "kill_switch_audit_log.jsonl" in captured.err


def test_cli_measure_fails_cleanly_when_cost_audit_log_cannot_be_read(capsys, tmp_path):
    storage_dir = tmp_path / "evidence"
    execution_dir = storage_dir / "exec_bad_cost_log"
    execution_dir.mkdir(parents=True)
    (execution_dir / "actions.json").write_text("[]", encoding="utf-8")
    (execution_dir / "cost_audit_log.jsonl").mkdir()
    exit_code = cli.main(["measure", "--execution-id", "exec_bad_cost_log", "--storage-dir", str(storage_dir)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "cost_audit_log.jsonl" in captured.err


def test_cli_measure_warns_explicitly_when_reproducibility_cross_check_finds_no_matching_execution_dir(
    capsys, tmp_path
):
    # Real gap found via independent review: if --storage-dir doesn't
    # contain ANY of the execution dirs a retest summary references (wrong
    # dir passed, or artifacts since cleaned up), cross_checked_against_
    # raw_artifact silently comes out as 0 with no WARNING key and no
    # distinguishing signal from "checked everything, 100% agreement" — a
    # JSON consumer would misread an entirely UNVERIFIED summary as
    # confirmed. Must surface this loudly instead.
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "runs": 2,
                "agreement_ratio": 1.0,
                "meets_recommended_threshold": True,
                "results": [
                    {"execution_id": "exec_a", "verdict": "confirmed"},
                    {"execution_id": "exec_b", "verdict": "confirmed"},
                ],
            }
        ),
        encoding="utf-8",
    )
    empty_storage_dir = tmp_path / "totally_empty"
    empty_storage_dir.mkdir()

    exit_code = cli.main(
        [
            "measure",
            "--retest-summary",
            str(summary_path),
            "--storage-dir",
            str(empty_storage_dir),
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 0
    assert report["reproducibility"]["cross_checked_against_raw_artifact"] == 0
    assert "WARNING_could_not_cross_check_any_run" in report["reproducibility"]
    assert "CẢNH BÁO" in captured.err


def test_cli_measure_warns_when_allowed_action_is_passed_without_execution_id(capsys, tmp_path):
    # Real gap found via independent review: --allowed-action silently had
    # zero effect if --execution-id wasn't also passed (the whole control-
    # effectiveness block is skipped) — an operator could believe their
    # allowlist was checked when it never was.
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(
        json.dumps({"runs": 0, "agreement_ratio": 0, "meets_recommended_threshold": True, "results": []}),
        encoding="utf-8",
    )
    exit_code = cli.main(
        ["measure", "--retest-summary", str(summary_path), "--allowed-action", "GET https://host/x"]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "không có tác dụng" in captured.err


def test_cli_report_renders_a_real_package_to_stdout(capsys, monkeypatch, tmp_path):
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_report_test"
    storage_dir = tmp_path / "evidence"
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))

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

    package_file = tmp_path / "package.json"
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
                "auth_local_test_1",
                "--scenario",
                "X-Content-Type-Options header missing on GET /",
                "--limitations",
                "Chỉ có role=main, thiếu positive/denied control.",
                "--next-action",
                "Không cần thêm.",
                "--format",
                "json",
            ]
        )
        == 0
    )
    package_file.write_text(capsys.readouterr().out, encoding="utf-8")

    exit_code = cli.main(["report", "--package-file", str(package_file)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "# Verification Package" in captured.out
    assert "tgt_test" in captured.out
    assert "X-Content-Type-Options header missing on GET /" in captured.out
    assert "Limitations (đọc trước tiên" in captured.out


def test_cli_report_writes_to_a_file_when_out_is_passed(capsys, monkeypatch, tmp_path):
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_report_out_test"
    storage_dir = tmp_path / "evidence"
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))

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

    package_file = tmp_path / "package.json"
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
                "auth_local_test_1",
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
    package_file.write_text(capsys.readouterr().out, encoding="utf-8")

    out_path = tmp_path / "report.md"
    exit_code = cli.main(["report", "--package-file", str(package_file), "--out", str(out_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == ""  # written to file, not stdout
    assert "Đã ghi báo cáo Markdown" in captured.err
    assert out_path.exists()
    assert "# Verification Package" in out_path.read_text(encoding="utf-8")


def test_cli_report_fails_cleanly_on_a_missing_file(capsys, tmp_path):
    exit_code = cli.main(["report", "--package-file", str(tmp_path / "nope.json")])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "không tìm thấy" in captured.err


def test_cli_report_fails_cleanly_when_package_top_level_is_not_an_object(capsys, tmp_path):
    package_file = tmp_path / "bad.json"
    package_file.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    exit_code = cli.main(["report", "--package-file", str(package_file)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "JSON object" in captured.err


def test_cli_report_fails_cleanly_on_invalid_package_content(capsys, tmp_path):
    package_file = tmp_path / "bad.json"
    package_file.write_text(json.dumps({"package_id": "pkg_1"}), encoding="utf-8")
    exit_code = cli.main(["report", "--package-file", str(package_file)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "không phải VerificationPackage hợp lệ" in captured.err


def test_cli_report_fails_cleanly_when_out_directory_does_not_exist(capsys, monkeypatch, tmp_path):
    # Real gap found via independent review: the --package-file read path
    # is fully hardened (FileNotFoundError/JSONDecodeError/non-dict-shape/
    # ValidationError all become a clean CliError), but the --out WRITE
    # path had no equivalent handling — writing to a parent directory that
    # doesn't exist crashed with a raw, uncaught FileNotFoundError instead
    # of the command's own error/exit-1 contract.
    import httpx

    db_path = str(tmp_path / "test.db")
    hypothesis_id = _create_stored_hypothesis(capsys, monkeypatch, db_path)
    execution_id = "exec_report_out_failure"
    storage_dir = tmp_path / "evidence"
    plan_file = _single_role_plan_file(tmp_path, hypothesis_id)

    _patch_evidence_harness_transport(monkeypatch, lambda request: httpx.Response(200, json={"ok": True}))

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

    package_file = tmp_path / "package.json"
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
                "auth_local_test_1",
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
    package_file.write_text(capsys.readouterr().out, encoding="utf-8")

    out_path = tmp_path / "no_such_directory" / "report.md"
    exit_code = cli.main(["report", "--package-file", str(package_file), "--out", str(out_path)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback" not in captured.err
    assert "không ghi được báo cáo" in captured.err
