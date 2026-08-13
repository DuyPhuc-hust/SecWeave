import re
from typing import Any

_FALSY_STRINGS = {"false", "0", "no", "null", "none", ""}

# Find the FIRST fence anywhere in the text — some models (e.g. Llama via
# Groq) don't just wrap JSON in ```json ... ``` but also add explanatory
# prose before/after the fence, even though the prompt asked for plain JSON.
# Requiring the whole response to START with the fence (as before) missed
# exactly this case.
_FENCE_PATTERN = re.compile(r"```[^\n]*\n(.*?)\n```", re.DOTALL)


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


def strip_markdown_json_fence(text: str) -> str:
    """LLMs often wrap JSON in ```json ... ``` even when the prompt asked for
    plain JSON — some models also add explanatory prose before/after the
    fence instead of just the fenced JSON. Finds the first fence anywhere in
    the response; if there is no fence at all, returns the text unchanged —
    doesn't try to guess/fix other kinds of malformed JSON, so a genuine JSON
    error is still reported correctly instead of being masked.

    Shared by every engine that parses JSON output from an LLM (Hypothesis
    Engine, Exploit Agent, ...) — not specific to any one engine.
    """
    match = _FENCE_PATTERN.search(text)
    if match:
        return match.group(1).strip()
    return text.strip()
