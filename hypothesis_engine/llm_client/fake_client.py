from typing import Callable, List, Optional

from hypothesis_engine.llm_client.base import HypothesisLLMClient


class FakeLLMClient(HypothesisLLMClient):
    """Stub có thể cấu hình, dùng cho unit test — không gọi API thật.

    Đây KHÔNG phải "fake LLM" theo nghĩa sản phẩm (không có đường CLI nào dùng
    class này) — đây là test double chuẩn để test logic parse/validate của
    HypothesisEngine một cách tất định, không phụ thuộc mạng/API key khi chạy
    `pytest`. Xem OpenAICompatibleLLMClient cho đường dùng LLM thật.
    """

    def __init__(
        self,
        responses: Optional[List[str]] = None,
        response_fn: Optional[Callable[[str], str]] = None,
    ) -> None:
        self._responses = list(responses) if responses else None
        self._response_fn = response_fn
        self.calls: List[str] = []

    def generate(self, prompt: str) -> str:
        self.calls.append(prompt)
        if self._response_fn is not None:
            return self._response_fn(prompt)
        if self._responses:
            return self._responses.pop(0)
        raise RuntimeError("FakeLLMClient chưa được cấu hình response nào")
