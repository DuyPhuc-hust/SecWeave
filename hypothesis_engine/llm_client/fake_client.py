from typing import Callable, List, Optional

from hypothesis_engine.llm_client.base import HypothesisLLMClient


class FakeLLMClient(HypothesisLLMClient):
    """Configurable stub used for unit tests — makes no real API calls.

    This is NOT a "fake LLM" in the product sense (no CLI path uses this
    class) — it's a standard test double for testing HypothesisEngine's
    parse/validate logic deterministically, without depending on the
    network/an API key when running `pytest`. See OpenAICompatibleLLMClient
    for the real-LLM path.
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
