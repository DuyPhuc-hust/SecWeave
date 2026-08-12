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


def test_cli_hypothesize_json_output_with_stubbed_real_client(capsys, monkeypatch):
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
        ]
    )
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert len(data) == 2
    assert data[0]["result"]["status"] == "hypothesis"
    assert data[0]["result"]["hypothesis"]["provenance"]["source_tool"] == "semgrep"
    assert "CẢNH BÁO" in captured.err


def test_cli_hypothesize_table_output_includes_provenance(capsys, monkeypatch):
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
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Provenance" in captured.out
    assert "source_tool=semgrep" in captured.out
    assert "source_signal_id=" in captured.out


class _RaisingClient:
    model = "raising-model"

    def generate(self, prompt: str) -> str:
        raise RuntimeError("LLM provider unreachable")


def test_cli_hypothesize_llm_call_failure_is_reported_cleanly_not_as_traceback(
    capsys, monkeypatch
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
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error: LLM provider unreachable" in captured.err
    assert "Traceback" not in captured.err


def test_cli_hypothesize_without_llm_env_vars_fails_cleanly(capsys, monkeypatch):
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
