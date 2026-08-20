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


def test_generate_raises_clean_runtime_error_when_content_is_null(monkeypatch):
    # Real gap found via independent review: a spec-compliant response
    # where the assistant message carries content=null (e.g. a tool-call-
    # only message, or a provider quirk) had the key PRESENT with value
    # None — dict access succeeded with no exception, so generate() used
    # to silently return None instead of a string, crashing every
    # downstream caller (strip_markdown_json_fence) with an unrelated,
    # confusing TypeError instead of this module's own clean RuntimeError.
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://example.com/v1")
    monkeypatch.setenv("LLM_MODEL", "test-model")

    def _fake_post(url, headers=None, json=None, timeout=None):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": None}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", _fake_post)

    client = OpenAICompatibleLLMClient()
    with pytest.raises(RuntimeError, match="không phải string"):
        client.generate("hello prompt")


def test_generate_raises_clean_runtime_error_on_malformed_base_url(monkeypatch):
    # Real gap found via independent review: httpx.InvalidURL (e.g. from a
    # bad port, or a stray control character from a copy-pasted .env value)
    # is NOT a subclass of httpx.HTTPError, so it wasn't caught by any of
    # cli.py's `except (RuntimeError, httpx.HTTPError)` handlers — crashed
    # with a raw traceback instead of this module's clean failure path.
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://example.com:not-a-port/v1")
    monkeypatch.setenv("LLM_MODEL", "test-model")

    client = OpenAICompatibleLLMClient()
    with pytest.raises(RuntimeError, match="LLM_BASE_URL không hợp lệ"):
        client.generate("hello prompt")


def test_generate_raises_clean_runtime_error_on_scheme_less_base_url(monkeypatch):
    # Real gap found via independent review: a whitespace-only/scheme-less
    # LLM_BASE_URL (e.g. a stray space from a copy-paste mistake) passes
    # the "env var is set" check, then raises httpx.UnsupportedProtocol —
    # NOT httpx.InvalidURL, so it skipped THIS module's own friendly
    # message (it's still an httpx.HTTPError subclass, so cli.py's own
    # handler doesn't crash on it, but the error was less helpful than it
    # should be).
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", " ")
    monkeypatch.setenv("LLM_MODEL", "test-model")

    client = OpenAICompatibleLLMClient()
    with pytest.raises(RuntimeError, match="LLM_BASE_URL không hợp lệ"):
        client.generate("hello prompt")


def test_base_url_strips_stray_whitespace_and_newlines(monkeypatch):
    # A trailing newline/CR in LLM_BASE_URL is a realistic .env copy-paste
    # mistake and would otherwise trigger httpx.InvalidURL.
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_BASE_URL", "https://example.com/v1/\n")
    monkeypatch.setenv("LLM_MODEL", "test-model")

    captured = {}

    def _fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", _fake_post)

    client = OpenAICompatibleLLMClient()
    client.generate("hello prompt")
    assert captured["url"] == "https://example.com/v1/chat/completions"
