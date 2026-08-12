from abc import ABC, abstractmethod
from typing import Any, Dict, List

from shared.models.signal import NormalizedSignal, RawReference, SignalCoverage


class SignalAdapter(ABC):
    tool_name: str

    @abstractmethod
    def parse(
        self,
        raw_report: Dict[str, Any],
        raw_reference: RawReference,
        tool_version: str,
        coverage: SignalCoverage,
    ) -> List[NormalizedSignal]:
        ...
