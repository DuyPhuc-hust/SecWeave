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


def container_as_list(
    container: Dict[str, Any], key: str, field_path: str, on_skip: Optional[OnSkipCallback] = None
) -> List[Any]:
    """Reads container[key], expecting a JSON list — a scanner report's
    container field (e.g. "results", "Vulnerabilities", "site", "alerts",
    "instances") should always be a list when present, but a corrupted or
    hand-edited report can have it present with `null` or some other JSON
    type instead. A MISSING key (a normal, expected shape — e.g. a Trivy
    result with vulnerabilities but no secrets) stays silent and returns
    `[]`; a key that IS PRESENT but isn't actually a list calls on_skip (if
    given) to surface the anomaly — collapsing "missing" and "present but
    wrong type" into the same silent case would hide real report corruption
    behind an ordinary, harmless shape.

    `{"results": null}` would otherwise make an adapter raise
    `TypeError: 'NoneType' object is not iterable` from a bare
    `enumerate(raw_report.get("results", []))` — `dict.get(key, default)`
    only substitutes the default when the key is MISSING, not when it's
    PRESENT with value `null`. Such a crash happens OUTSIDE any per-item
    try/except (the `enumerate()` call itself runs before the loop body,
    and its try/except, is ever entered), discarding every signal already
    parsed from the same report — not just skipping one bad entry, which
    violates the "must not lose others" contract above just as much as a
    single bad item would.
    """
    value = container.get(key)
    if isinstance(value, list):
        return value
    if key in container and on_skip:
        on_skip(f"'{field_path}' không phải là list (giá trị thực tế: {type(value).__name__}) — coi như rỗng.")
    return []
