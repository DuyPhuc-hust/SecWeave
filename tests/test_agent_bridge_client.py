import pytest

from hypothesis_engine.llm_client.agent_bridge_client import AgentBridgeLLMClient


def test_generate_writes_prompt_and_returns_response(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))

    def _fake_wait(prompt_path, response_path):
        assert prompt_path.read_text(encoding="utf-8") == "some prompt"
        response_path.write_text('{"verifiable": true}', encoding="utf-8")

    monkeypatch.setattr(client, "_wait_for_agent", _fake_wait)

    result = client.generate("some prompt")

    assert result == '{"verifiable": true}'
    assert (tmp_path / "prompt_1.txt").read_text(encoding="utf-8") == "some prompt"


def test_generate_raises_if_agent_never_writes_response(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))
    monkeypatch.setattr(client, "_wait_for_agent", lambda prompt_path, response_path: None)

    with pytest.raises(RuntimeError, match="response"):
        client.generate("some prompt")


def test_generate_uses_incrementing_file_names_per_call(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))

    def _fake_wait(prompt_path, response_path):
        response_path.write_text("ok", encoding="utf-8")

    monkeypatch.setattr(client, "_wait_for_agent", _fake_wait)

    client.generate("first")
    client.generate("second")

    assert (tmp_path / "prompt_1.txt").read_text(encoding="utf-8") == "first"
    assert (tmp_path / "prompt_2.txt").read_text(encoding="utf-8") == "second"


def test_wait_for_agent_raises_clear_error_on_eof(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))

    def _raise_eof(_prompt: str) -> str:
        raise EOFError()

    monkeypatch.setattr("builtins.input", _raise_eof)

    with pytest.raises(RuntimeError, match="terminal tương tác"):
        client.generate("some prompt")


def test_generate_removes_stale_response_before_waiting(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))
    stale_response = tmp_path / "response_1.txt"
    stale_response.write_text("dữ liệu cũ từ lần chạy trước", encoding="utf-8")

    seen_exists_before_wait = {}

    def _fake_wait(prompt_path, response_path):
        seen_exists_before_wait["value"] = response_path.exists()
        response_path.write_text("fresh", encoding="utf-8")

    monkeypatch.setattr(client, "_wait_for_agent", _fake_wait)
    result = client.generate("prompt")

    assert seen_exists_before_wait["value"] is False
    assert result == "fresh"
