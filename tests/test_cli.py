import json
from pathlib import Path

import pytest

import cli

SEMGREP_FIXTURE = str(Path(__file__).parent / "fixtures" / "semgrep_sample_report.json")


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
    assert len(data) == 2
    assert data[0]["rule"]["id"] == "python.django.security.audit.sqli"
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
    assert "python.django.security.audit.sqli" in captured.out
    assert "2 NormalizedSignal" in captured.out


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
    """Đứng thay OpenAICompatibleLLMClient trong test CLI — không gọi API thật.

    Test CLI phải xác nhận đúng luồng nối dây (normalize -> engine -> in kết
    quả), không phải xác nhận provider thật trả lời đúng — nên monkeypatch
    class thật bằng stub này, không cần LLM_API_KEY/LLM_BASE_URL/LLM_MODEL.
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
    assert len(data) == 2
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

    # hypothesis_id không tồn tại cho bản ghi not_verifiable — phải tra được
    # qua --signal-id, đúng phần vừa fix.
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
    # Trỏ --context-db vào 1 thư mục (không phải file) khiến sqlite3.connect lỗi.
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
    """Thành công lần gọi đầu, lỗi từ lần thứ 2 trở đi — mô phỏng 1 signal giữa
    chừng bị lỗi mạng sau khi (các) signal trước đã sinh hypothesis thành công.
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

    # Lượt chạy vẫn báo lỗi (không giả vờ thành công)...
    assert exit_code == 1
    assert "error: simulated failure on later signal" in captured.err
    # ...nhưng signal đầu đã thành công thì vẫn phải xuất hiện trong output...
    assert len(data) == 1
    hypothesis_id = data[0]["result"]["hypothesis"]["hypothesis_id"]
    # ...và thực sự được ghi vào Context Store, không bị vứt bỏ.
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
    # SEMGREP_FIXTURE có 2 finding — xác nhận cả 2 được xử lý qua ĐÚNG 1 lần
    # chờ agent (không phải 2 lần), và cả 2 vẫn được lưu đúng vào Context Store.
    import hypothesis_engine.llm_client.agent_bridge_client as agent_module

    wait_calls = []

    def _fake_wait(self, prompt_path, response_path):
        wait_calls.append(prompt_path)
        response_path.write_text(
            json.dumps(
                [
                    {
                        "verifiable": True,
                        "expected_behavior": "a",
                        "suspected_behavior": "b",
                        "observation_criteria": "c",
                    },
                    {"verifiable": False, "reason": "not enough context"},
                ]
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(agent_module.AgentBridgeLLMClient, "_wait_for_agent", _fake_wait)
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
    assert len(data) == 2
    assert data[0]["result"]["status"] == "hypothesis"
    assert data[1]["result"]["status"] == "not_verifiable"
