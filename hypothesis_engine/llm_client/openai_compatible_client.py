import os

import httpx

from hypothesis_engine.llm_client.base import HypothesisLLMClient

REQUIRED_ENV_VARS = ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL")


class OpenAICompatibleLLMClient(HypothesisLLMClient):
    """Gọi bất kỳ provider nào có endpoint tương thích chuẩn OpenAI Chat
    Completions — OpenAI, Google Gemini, Groq, Together AI, v.v. Đổi provider
    chỉ cần đổi 3 biến môi trường, không đổi dòng code nào.

    Dùng httpx (đã là dependency có sẵn của project) thay vì cài thêm SDK
    riêng cho từng provider — đúng nguyên tắc SPEC §10.1 "thay thế được,
    không ràng buộc dài hạn với một nhà cung cấp".
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
        self._base_url = values["LLM_BASE_URL"].rstrip("/")
        self.model = values["LLM_MODEL"]
        self._timeout = timeout

    def generate(self, prompt: str) -> str:
        response = httpx.post(
            f"{self._base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={"model": self.model, "messages": [{"role": "user", "content": prompt}]},
            timeout=self._timeout,
        )
        response.raise_for_status()
        try:
            body = response.json()
            return body["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                f"Response từ LLM provider không đúng format OpenAI chat completions "
                f"(thiếu choices[0].message.content): {exc}"
            ) from exc
