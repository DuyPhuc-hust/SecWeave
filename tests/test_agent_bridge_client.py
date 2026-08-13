import json

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
    prompt_path = tmp_path / f"prompt_{client._run_id}_1.txt"
    assert prompt_path.read_text(encoding="utf-8") == "some prompt"


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

    assert (tmp_path / f"prompt_{client._run_id}_1.txt").read_text(encoding="utf-8") == "first"
    assert (tmp_path / f"prompt_{client._run_id}_2.txt").read_text(encoding="utf-8") == "second"


def test_two_clients_in_same_work_dir_do_not_collide(tmp_path, monkeypatch):
    # Mô phỏng 2 process CLI riêng biệt cùng chạy --llm-mode agent trong cùng
    # work_dir — mỗi client có run_id riêng nên không đè lên prompt/response
    # của nhau, dù bộ đếm nội bộ của mỗi client đều bắt đầu từ 1.
    client_a = AgentBridgeLLMClient(work_dir=str(tmp_path))
    client_b = AgentBridgeLLMClient(work_dir=str(tmp_path))
    assert client_a._run_id != client_b._run_id

    monkeypatch.setattr(
        client_a, "_wait_for_agent", lambda p, r: r.write_text("from A", encoding="utf-8")
    )
    client_a.generate("prompt from A")

    prompt_path_a = tmp_path / f"prompt_{client_a._run_id}_1.txt"
    prompt_path_b_would_be = tmp_path / f"prompt_{client_b._run_id}_1.txt"
    assert prompt_path_a.read_text(encoding="utf-8") == "prompt from A"
    assert not prompt_path_b_would_be.exists()


def test_wait_for_agent_raises_clear_error_on_eof(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))

    def _raise_eof(_prompt: str) -> str:
        raise EOFError()

    monkeypatch.setattr("builtins.input", _raise_eof)

    with pytest.raises(RuntimeError, match="terminal tương tác"):
        client.generate("some prompt")


def test_generate_removes_stale_response_before_waiting(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))
    stale_response = tmp_path / f"response_{client._run_id}_1.txt"
    stale_response.write_text("dữ liệu cũ từ lần chạy trước", encoding="utf-8")

    seen_exists_before_wait = {}

    def _fake_wait(prompt_path, response_path):
        seen_exists_before_wait["value"] = response_path.exists()
        response_path.write_text("fresh", encoding="utf-8")

    monkeypatch.setattr(client, "_wait_for_agent", _fake_wait)
    result = client.generate("prompt")

    assert seen_exists_before_wait["value"] is False
    assert result == "fresh"


def test_generate_many_writes_one_combined_prompt_and_waits_once(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))
    wait_calls = []

    def _fake_wait(prompt_path, response_path):
        wait_calls.append(prompt_path)
        response_path.write_text(
            json.dumps([{"verifiable": True}, {"verifiable": False, "reason": "x"}]),
            encoding="utf-8",
        )

    monkeypatch.setattr(client, "_wait_for_agent", _fake_wait)

    results = client.generate_many(["prompt A", "prompt B"])

    assert len(wait_calls) == 1  # đúng 1 lần chờ cho cả 2 prompt, không phải 2
    combined_prompt = wait_calls[0].read_text(encoding="utf-8")
    assert "prompt A" in combined_prompt
    assert "prompt B" in combined_prompt
    assert "SIGNAL 1/2" in combined_prompt
    assert "SIGNAL 2/2" in combined_prompt

    assert results == [
        json.dumps({"verifiable": True}),
        json.dumps({"verifiable": False, "reason": "x"}),
    ]


def test_generate_many_raises_clean_error_on_wrong_array_length(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))

    def _fake_wait(prompt_path, response_path):
        response_path.write_text(json.dumps([{"verifiable": True}]), encoding="utf-8")

    monkeypatch.setattr(client, "_wait_for_agent", _fake_wait)

    with pytest.raises(RuntimeError, match="đúng 2 phần tử"):
        client.generate_many(["prompt A", "prompt B"])


def test_generate_many_raises_clean_error_on_non_array_response(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))

    def _fake_wait(prompt_path, response_path):
        response_path.write_text(json.dumps({"verifiable": True}), encoding="utf-8")

    monkeypatch.setattr(client, "_wait_for_agent", _fake_wait)

    with pytest.raises(RuntimeError, match="JSON array"):
        client.generate_many(["prompt A", "prompt B"])


def test_generate_many_raises_clean_error_on_invalid_json(tmp_path, monkeypatch):
    client = AgentBridgeLLMClient(work_dir=str(tmp_path))

    def _fake_wait(prompt_path, response_path):
        response_path.write_text("not json at all", encoding="utf-8")

    monkeypatch.setattr(client, "_wait_for_agent", _fake_wait)

    with pytest.raises(RuntimeError, match="JSON array hợp lệ"):
        client.generate_many(["prompt A", "prompt B"])
