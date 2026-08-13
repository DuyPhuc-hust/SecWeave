from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

from shared.models.signal import NormalizedSignal, RawReference, SignalCoverage

OnSkipCallback = Callable[[str], None]


class SignalAdapter(ABC):
    tool_name: str

    @abstractmethod
    def parse(
        self,
        raw_report: Dict[str, Any],
        raw_reference: RawReference,
        tool_version: str,
        coverage: SignalCoverage,
        on_skip: Optional[OnSkipCallback] = None,
    ) -> List[NormalizedSignal]:
        """Converts raw_report into a list of NormalizedSignal.

        One bad entry (missing required field, wrong type) must not lose the
        other valid entries in the same report — the adapter must skip
        exactly that entry, call on_skip(reason description) if provided,
        and keep processing the rest.
        """
        ...
