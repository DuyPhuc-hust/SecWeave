import httpx
import pytest

from hypothesis_engine.llm_client.openai_compatible_client import OpenAICompatibleLLMClient


def _clear_env(monkeypatch):
    for var in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)


def test_missing_all_env_vars_lists_all_of_them(monkeypatch):
    _clear_env(monkeypatch)
    with pytest.raises(RuntimeError) as exc_info:
        OpenAICompatibleLLMClient()
    message = str(exc_info.value)
    assert "LLM_API_KEY" in message
    assert "LLM_BASE_URL" in message
    assert "LLM_MODEL" in message


def test_missing_one_env_var_still_raises(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    with pytest.raises(RuntimeError, match="LLM_BASE_URL"):
        OpenAICompatibleLLMClient()


def test_generate_calls_chat_completions_endpoint_and_parses_response(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://example.com/v1/")
    monkeypatch.setenv("LLM_MODEL", "test-model")

    captured_request = {}

    def _fake_post(url, headers=None, json=None, timeout=None):
        captured_request["url"] = url
        captured_request["headers"] = headers
        captured_request["json"] = json
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"verifiable": false, "reason": "x"}'}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", _fake_post)

    client = OpenAICompatibleLLMClient()
    result = client.generate("hello prompt")

    assert result == '{"verifiable": false, "reason": "x"}'
    assert captured_request["url"] == "https://example.com/v1/chat/completions"
    assert captured_request["headers"]["Authorization"] == "Bearer test-key"
    assert captured_request["json"]["model"] == "test-model"
    assert captured_request["json"]["messages"] == [{"role": "user", "content": "hello prompt"}]


def test_generate_raises_on_http_error(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://example.com/v1")
    monkeypatch.setenv("LLM_MODEL", "test-model")

    def _fake_post(url, headers=None, json=None, timeout=None):
        return httpx.Response(401, json={"error": "unauthorized"}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", _fake_post)

    client = OpenAICompatibleLLMClient()
    with pytest.raises(httpx.HTTPStatusError):
        client.generate("hello prompt")


@pytest.mark.parametrize(
    "body",
    [
        {"choices": []},
        {},
        {"choices": [{"message": {}}]},
        {"choices": [{}]},
    ],
)
def test_generate_raises_clean_runtime_error_on_malformed_200_response(monkeypatch, body):
    # HTTP 200 but the body doesn't match the OpenAI chat completions shape
    # (content filtering, a proxy error, a not-truly-compatible endpoint...)
    # — raise_for_status() doesn't catch this since the status is still 200,
    # so the shape must be checked explicitly.
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://example.com/v1")
    monkeypatch.setenv("LLM_MODEL", "test-model")

    def _fake_post(url, headers=None, json=None, timeout=None):
        return httpx.Response(200, json=body, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", _fake_post)

    client = OpenAICompatibleLLMClient()
    with pytest.raises(RuntimeError, match="không đúng format OpenAI chat completions"):
        client.generate("hello prompt")


def test_generate_raises_clean_runtime_error_on_non_json_200_response(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://example.com/v1")
    monkeypatch.setenv("LLM_MODEL", "test-model")

    def _fake_post(url, headers=None, json=None, timeout=None):
        return httpx.Response(
            200, content=b"not json at all", request=httpx.Request("POST", url)
        )

    monkeypatch.setattr(httpx, "post", _fake_post)

    client = OpenAICompatibleLLMClient()
    with pytest.raises(RuntimeError, match="không đúng format OpenAI chat completions"):
        client.generate("hello prompt")
