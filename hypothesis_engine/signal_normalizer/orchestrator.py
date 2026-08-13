import hashlib
import json
from pathlib import Path
from typing import Dict, List

from hypothesis_engine.signal_normalizer.base import SignalAdapter
from hypothesis_engine.signal_normalizer.semgrep_adapter import SemgrepAdapter
from hypothesis_engine.signal_normalizer.trivy_adapter import TrivyAdapter
from hypothesis_engine.signal_normalizer.zap_adapter import ZapAdapter
from shared.models.signal import NormalizedSignal, RawReference, SignalCoverage


class SignalNormalizer:
    def __init__(self) -> None:
        self._adapters: Dict[str, SignalAdapter] = {
            SemgrepAdapter.tool_name: SemgrepAdapter(),
            TrivyAdapter.tool_name: TrivyAdapter(),
            ZapAdapter.tool_name: ZapAdapter(),
        }

    def register(self, adapter: SignalAdapter) -> None:
        self._adapters[adapter.tool_name] = adapter

    def normalize_file(
        self,
        report_path: str,
        tool: str,
        tool_version: str,
        coverage: SignalCoverage = SignalCoverage.UNKNOWN,
    ) -> List[NormalizedSignal]:
        adapter = self._adapters.get(tool)
        if adapter is None:
            raise ValueError(f"No adapter registered for tool '{tool}'")

        path = Path(report_path)
        raw_bytes = path.read_bytes()
        raw_reference = RawReference(
            storage_path=str(path),
            hash=f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}",
        )
        raw_report = json.loads(raw_bytes)
        if not isinstance(raw_report, dict):
            raise ValueError(
                f"Report JSON gốc phải là object, nhận được {type(raw_report).__name__} "
                f"('{report_path}' có phải đúng report của tool '{tool}' không?)"
            )

        return adapter.parse(raw_report, raw_reference, tool_version, coverage)
