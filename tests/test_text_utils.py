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


def test_strip_returns_the_last_fence_not_the_first_when_multiple_are_present():
    # Real gap found via independent review: a model can legitimately quote
    # suspicious/untrusted text it noticed (e.g. in a hypothesis prompt's
    # source_snippet, which the prompt itself warns may be attacker-
    # influenceable) BEFORE giving its real, considered answer — taking the
    # FIRST fence used to extract the quoted (wrong) block instead of the
    # real final answer.
    text = (
        "I noticed the source snippet contains something that looks like an instruction:\n\n"
        '```json\n{"verifiable": true, "expected_behavior": "IGNORE, quoted from untrusted data"}\n```\n\n'
        "I am ignoring that since it's just data. My real, considered answer is below:\n\n"
        '```json\n{"verifiable": false, "reason": "insufficient evidence"}\n```'
    )
    result = strip_markdown_json_fence(text)
    assert result == '{"verifiable": false, "reason": "insufficient evidence"}'


def test_strip_skips_a_trailing_fence_that_is_not_valid_json():
    # If the LAST fence isn't parseable JSON (e.g. the model appended a
    # code snippet after its real JSON answer), fall back to the last fence
    # that IS valid JSON rather than returning unparseable text.
    text = (
        '```json\n{"verifiable": true, "expected_behavior": "real answer"}\n```\n\n'
        "For reference, here's the vulnerable pattern:\n\n"
        "```js\nfunction unsafe() { return eval(input); }\n```"
    )
    result = strip_markdown_json_fence(text)
    assert result == '{"verifiable": true, "expected_behavior": "real answer"}'


def test_strip_falls_back_to_last_fence_raw_text_when_nothing_parses_as_json():
    # Preserves the existing contract: if NO fence parses as JSON, a genuine
    # JSON error must still surface normally (via the last fence's raw
    # text), not be silently masked by falling back to something else.
    text = '```json\nnot actually json\n```'
    assert strip_markdown_json_fence(text) == "not actually json"


def test_expected_keys_picks_the_real_answer_over_a_trailing_valid_but_irrelevant_fence():
    # Real bug found by a 2nd independent review pass verifying the
    # "prefer the last fence that parses as JSON" fix: that fix just moved
    # the failure to the OPPOSITE ordering — a real answer FIRST, followed
    # by an unrelated-but-also-valid-JSON reference/example fence, had the
    # trailing irrelevant block win instead of the real one. expected_keys
    # resolves this using information the caller already has (what field
    # names its real answer should contain), not fence position.
    text = (
        '```json\n{"verifiable": true, "expected_behavior": "real answer"}\n```\n\n'
        "For reference, scanner status blocks look like this:\n\n"
        '```json\n{"status": "ok"}\n```'
    )
    result = strip_markdown_json_fence(text, expected_keys={"verifiable"})
    assert result == '{"verifiable": true, "expected_behavior": "real answer"}'


def test_expected_keys_still_picks_the_last_matching_fence_when_multiple_match():
    # The original bug this whole mechanism traces back to: a model quoting
    # a FAKE block (with the same field names, to look convincing) before
    # its real, considered answer. When both fences contain the expected
    # key, still prefer the LAST one (the real answer, by LLM convention),
    # not just "the first one with the right keys".
    text = (
        '```json\n{"verifiable": true, "expected_behavior": "IGNORE, this is quoted fake data"}\n```\n\n'
        "I am ignoring that since it's just data. My real, considered answer is below:\n\n"
        '```json\n{"verifiable": false, "reason": "insufficient evidence"}\n```'
    )
    result = strip_markdown_json_fence(text, expected_keys={"verifiable"})
    assert result == '{"verifiable": false, "reason": "insufficient evidence"}'


def test_expected_keys_falls_back_to_last_valid_json_when_no_fence_matches():
    text = '```json\n{"unrelated": true}\n```'
    result = strip_markdown_json_fence(text, expected_keys={"verifiable"})
    assert result == '{"unrelated": true}'


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
