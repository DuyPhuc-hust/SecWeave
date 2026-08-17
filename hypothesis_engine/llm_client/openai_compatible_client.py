import os

import httpx

from hypothesis_engine.llm_client.base import HypothesisLLMClient

REQUIRED_ENV_VARS = ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL")


class OpenAICompatibleLLMClient(HypothesisLLMClient):
    """Calls any provider with an endpoint compatible with the standard
    OpenAI Chat Completions format — OpenAI, Google Gemini, Groq, Together
    AI, etc. Switching providers only requires changing 3 environment
    variables, not a single line of code.

    Uses httpx (already a dependency of the project) instead of installing a
    separate SDK per provider — in line with SPEC §10.1's principle of
    "replaceable, no long-term lock-in with one provider".
    """

    def __init__(self, timeout: float = 30.0) -> None:
        values = {name: os.environ.get(name) for name in REQUIRED_ENV_VARS}
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise RuntimeError(
                f"Thiếu biến môi trường: {', '.join(missing)}. Cần đủ cả 3: "
                "LLM_API_KEY (key của provider), LLM_BASE_URL (endpoint gốc, "
                "ví dụ https://generativelanguage.googleapis.com/v1beta/openai cho "
                "Gemini hoặc https://api.openai.com/v1 cho OpenAI), LLM_MODEL (tên model)."
            )

        self._api_key = values["LLM_API_KEY"]
        # .strip() (not just .rstrip("/")) — a stray trailing newline/CR is a
        # realistic .env copy-paste mistake and is exactly the kind of input
        # that makes httpx raise InvalidURL below; stripping it here fixes
        # the common case outright instead of only relying on that guard.
        self._base_url = values["LLM_BASE_URL"].strip().rstrip("/")
        self.model = values["LLM_MODEL"]
        self._timeout = timeout

    def generate(self, prompt: str) -> str:
        try:
            response = httpx.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={"model": self.model, "messages": [{"role": "user", "content": prompt}]},
                timeout=self._timeout,
            )
        except httpx.InvalidURL as exc:
            # Real gap found via independent review: a malformed
            # LLM_BASE_URL (a bad port, a stray control character) raises
            # httpx.InvalidURL — NOT a subclass of httpx.HTTPError, so none
            # of cli.py's `except (RuntimeError, httpx.HTTPError)` handlers
            # caught it, crashing with a raw traceback instead of this
            # module's otherwise-clean failure path. Same httpx quirk
            # already found and fixed once in evidence_harness/harness.py.
            raise RuntimeError(f"LLM_BASE_URL không hợp lệ ('{self._base_url}'): {exc}") from exc
        response.raise_for_status()
        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                f"Response từ LLM provider không đúng format OpenAI chat completions "
                f"(thiếu choices[0].message.content): {exc}"
            ) from exc
        if not isinstance(content, str):
            # Real gap found via independent review: a spec-compliant
            # response where the assistant message carries content=null
            # (e.g. a tool-call-only message, or a provider quirk) has the
            # key PRESENT with value None — the dict access above succeeds
            # with no exception, so this used to silently return None
            # instead of a string, crashing every downstream caller
            # (strip_markdown_json_fence) with an unrelated, confusing
            # TypeError instead of this module's own clean RuntimeError.
            raise RuntimeError(
                f"Response từ LLM provider có choices[0].message.content không phải string "
                f"(kiểu thực tế: {type(content).__name__}) — provider có thể trả tool-call thay vì text."
            )
        return content
