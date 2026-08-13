import pytest

from shared.text_utils import is_truthy, strip_markdown_json_fence


def test_strip_returns_plain_json_unchanged():
    assert strip_markdown_json_fence('{"a": 1}') == '{"a": 1}'


def test_strip_removes_fence_wrapping_entire_response():
    text = '```json\n{"a": 1}\n```'
    assert strip_markdown_json_fence(text) == '{"a": 1}'


def test_strip_removes_fence_with_no_language_tag():
    text = '```\n{"a": 1}\n```'
    assert strip_markdown_json_fence(text) == '{"a": 1}'


def test_strip_extracts_json_from_fence_surrounded_by_prose():
    # Real regression: Llama (via Groq) returns explanatory prose both
    # before AND after the fence, not just clean JSON in a fence like
    # Gemini — the old version only handled the case where the response
    # STARTS with the fence, missing exactly this case.
    text = (
        "Đây là kế hoạch hành động:\n\n"
        '```json\n{"plannable": true, "actions": []}\n```\n\n'
        "Lưu ý: các bước trên chỉ mang tính quan sát."
    )
    assert strip_markdown_json_fence(text) == '{"plannable": true, "actions": []}'


def test_strip_returns_text_unchanged_when_no_fence_present():
    text = "not json at all, no fence here"
    assert strip_markdown_json_fence(text) == text


@pytest.mark.parametrize(
    "value,expected",
    [
        (True, True),
        (False, False),
        ("true", True),
        ("false", False),
        ("True", True),
        ("0", False),
        ("no", False),
        ("null", False),
        ("", False),
        (None, False),
        (1, True),
        (0, False),
    ],
)
def test_is_truthy_handles_common_llm_representations(value, expected):
    assert is_truthy(value) is expected
