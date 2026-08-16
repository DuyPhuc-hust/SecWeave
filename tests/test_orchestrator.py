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


@pytest.mark.parametrize("bad_content", ["[1, 2, 3]", '"just a string"', "42", "null"])
def test_non_object_top_level_json_raises_clean_value_error(tmp_path, bad_content):
    bad_file = tmp_path / "bad_report.json"
    bad_file.write_text(bad_content, encoding="utf-8")

    normalizer = SignalNormalizer()
    with pytest.raises(ValueError, match="phải là object"):
        normalizer.normalize_file(
            report_path=str(bad_file), tool="semgrep", tool_version="1.78.0"
        )


def test_pathologically_deep_json_raises_clean_value_error_not_recursion_error(tmp_path):
    # Real bug found via independent review: ordinary malformed JSON raises
    # json.JSONDecodeError (a ValueError subclass, caught cleanly), but a
    # syntactically VALID, pathologically deeply-nested document raises
    # RecursionError instead — not a ValueError, so it used to escape
    # uncaught and dump a raw traceback instead of a clean CLI error.
    bad_file = tmp_path / "too_deep.json"
    depth = 200_000
    bad_file.write_text(("[" * depth) + ("]" * depth), encoding="utf-8")

    normalizer = SignalNormalizer()
    with pytest.raises(ValueError, match="lồng quá sâu"):
        normalizer.normalize_file(report_path=str(bad_file), tool="semgrep", tool_version="1.78.0")
