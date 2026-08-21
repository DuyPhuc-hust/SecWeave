import json
import re
from typing import Any, Iterable, Optional

_FALSY_STRINGS = {"false", "0", "no", "null", "none", ""}

# Find the FIRST fence anywhere in the text — some models (e.g. Llama via
# Groq) don't just wrap JSON in ```json ... ``` but also add explanatory
# prose before/after the fence, even though the prompt asked for plain JSON.
# Requiring the whole response to START with the fence (as before) missed
# exactly this case.
#
# The closing `\n?` is deliberately OPTIONAL — a model emitting compact,
# single-line JSON with no blank line before the closing ``` (a plausible,
# terser style, not just the multi-line style every existing test case
# used) would otherwise not match a pattern that hard-required a `\n`
# before the closing fence, silently falling through to
# `return text.strip()` with the fence markers still embedded — a raw
# `json.loads()` failure downstream instead of a clean extraction.
_FENCE_PATTERN = re.compile(r"```[^\n]*\n(.*?)\n?```", re.DOTALL)


def is_truthy(value: Any) -> bool:
    """LLMs sometimes return a bool field ("verifiable"/"plannable") as a
    string ("false"/"true") or a number (0/1) instead of a plain JSON bool —
    `value is False` only catches the real bool and misses these other
    representations of "false", losing the LLM's actual reason. Shared by
    every engine that parses JSON output from an LLM.
    """
    if isinstance(value, str):
        return value.strip().lower() not in _FALSY_STRINGS
    return bool(value)


def strip_markdown_json_fence(text: str, expected_keys: Optional[Iterable[str]] = None) -> str:
    """LLMs often wrap JSON in ```json ... ``` even when the prompt asked for
    plain JSON — some models also add explanatory prose before/after the
    fence instead of just the fenced JSON. If there is no fence at all,
    returns the text unchanged — doesn't try to guess/fix other kinds of
    malformed JSON, so a genuine JSON error is still reported correctly
    instead of being masked.

    Shared by every engine that parses JSON output from an LLM (Hypothesis
    Engine, Exploit Agent, ...) — not specific to any one engine.

    `expected_keys` (e.g. `{"verifiable"}` for Hypothesis Engine,
    `{"plannable"}` for Exploit Agent): when given, prefers the LAST fence
    whose parsed JSON is an object containing at least one of these keys —
    resolving ambiguity using information the CALLER already has (what
    shape its own real answer takes), rather than guessing from fence
    position alone. Neither "first fence" nor "last fence" is reliable on
    its own: a model can legitimately quote suspicious text it noticed in
    untrusted input (e.g. a hypothesis prompt's `source_snippet`, which the
    prompt itself warns may contain adversarial content) before giving its
    real answer, and a real answer can equally be followed by an
    unrelated-but-also-valid-JSON reference/illustration fence. Falls back
    to the position-only heuristic (last fence that's valid JSON) when no
    fence's keys match (or `expected_keys` isn't given).
    """
    matches = list(_FENCE_PATTERN.finditer(text))
    if not matches:
        return text.strip()

    parsed_candidates = []
    for match in matches:
        candidate = match.group(1).strip()
        try:
            parsed: Any = json.loads(candidate)
        except json.JSONDecodeError:
            parsed = None
        parsed_candidates.append((candidate, parsed))

    if expected_keys:
        expected_keys = set(expected_keys)
        for candidate, parsed in reversed(parsed_candidates):
            if isinstance(parsed, dict) and expected_keys & parsed.keys():
                return candidate

    # No expected_keys given, or none of the fences' parsed objects matched
    # any of them — fall back to the last fence that's valid JSON at all,
    # else the very last fence's raw text (so a genuine JSON error still
    # surfaces normally rather than being masked).
    for candidate, parsed in reversed(parsed_candidates):
        if parsed is not None:
            return candidate
    return parsed_candidates[-1][0]
