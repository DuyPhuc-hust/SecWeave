from abc import ABC, abstractmethod


class HypothesisLLMClient(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> str:
        ...
