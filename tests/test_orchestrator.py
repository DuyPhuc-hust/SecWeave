from pathlib import Path

import pytest

from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_sample_report.json"


def test_unknown_tool_raises_value_error():
    normalizer = SignalNormalizer()
    with pytest.raises(ValueError):
        normalizer.normalize_file(
            report_path=str(FIXTURE), tool="unknown_tool", tool_version="0"
        )
