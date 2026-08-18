import re
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import unquote, urlsplit

from shared.models.action import ActionSpec, PolicyDecision
from shared.models.entities import Authorization

# SPEC §4.2: "actions that delete/modify existing data, change configuration,
# impact service availability, or perform broad-scope scanning ... must never
# be added to the allowlist under any circumstances" — hard-blocked here,
# independent of allowlist content (a misconfigured allowlist can't unlock
# these methods either).
FORBIDDEN_METHODS = {"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"}


def _path_template_to_regex(template: str) -> re.Pattern:
    # "/api/objects/{id}" -> each {..} matches exactly 1 path segment (never
    # matches "/"). Doesn't add its own ^/$ — the caller uses fullmatch()
    # instead of match() with "$", to avoid depending on the subtle semantics
    # of "$" (which also matches right before a trailing newline) — urlsplit()
    # already strips control characters so this hasn't been exploitable
    # through that path, but fullmatch() is simpler and more certain anyway.
    segments = re.split(r"(\{[^/{}]+\})", template)
    regex_parts = [
        r"[^/]+" if seg.startswith("{") and seg.endswith("}") else re.escape(seg)
        for seg in segments
    ]
    return re.compile("".join(regex_parts))


_MAX_DECODE_PASSES = 5


def _decode_path_safely(path: str) -> Optional[str]:
    """Percent-decodes a URL path before matching it against an allowlist
    path template. Real bypass found via independent review: matching the
    RAW (still percent-encoded) path let a segment like "%2e%2e%2fadmin"
    satisfy a "{id}" placeholder's `[^/]+` regex (no literal "/" in the raw
    text) — but httpx sends the raw encoded path unchanged on the wire, and
    the real target (or any proxy in front of it) may decode+normalize it
    into "/api/objects/../admin" -> "/api/admin", escaping the allowlisted
    scope entirely. Returns None (caller must deny) if decoding (up to
    _MAX_DECODE_PASSES rounds, to also catch double-encoding like
    "%252e%252e%252fadmin" — a second real bypass an independent review
    found in the first, single-pass version of this function) reveals a
    "/" that wasn't literally present in the ORIGINAL raw path (an encoded
    slash would change the segment structure the template was matched
    against), a backslash (never legitimate here, and the exact separator
    a Windows/IIS-style backend would treat as a path boundary — the
    review's second finding), or a "."/".." segment (never legitimate for
    a single {id}-style path segment). Denies outright if decoding hasn't
    stabilized within _MAX_DECODE_PASSES rounds, rather than risk matching
    against a still-partially-encoded string.
    """
    decoded = path
    for _ in range(_MAX_DECODE_PASSES):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    else:
        return None
    if decoded.count("/") != path.count("/"):
        return None
    if "\\" in decoded:
        return None
    if any(segment in (".", "..") for segment in decoded.split("/")):
        return None
    return decoded


_PARAMS_CLAUSE_PREFIX = "params:"


def _split_top_level_commas(text: str) -> List[str]:
    """Splits on commas that aren't nested inside {}, (), or [] — so a
    bounded-repetition quantifier like the "2,4" in "^a{2,4}$" (the single
    most natural way to write "N-digit id") survives intact instead of
    being cut in half. Real bug found via independent review: a naive
    text.split(",") silently mangled any key=regex pair using such a
    quantifier into a near-useless truncated pattern (`^a{2`) AND created a
    bogus extra allowlist key from the leftover text (`4}$`, mapped to "no
    value constraint") — corrupting the operator's allowlist without ever
    raising an error.
    """
    parts = []
    depth = 0
    current: List[str] = []
    for ch in text:
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _parse_allowed_params(extra_tokens: List[str]) -> Optional[Dict[str, Optional[re.Pattern]]]:
    """Parses the optional 3rd token of an allowlist entry — `params:a,b,c`
    — into the parameter keys that entry permits, each optionally paired
    with a value pattern via `key=regex` (e.g. `params:userId=^\\d+$,threshold`).
    A key with no `=regex` suffix permits any value for that key (previous,
    name-only behaviour — kept for backward compatibility with existing
    allowlist strings). No 3rd token means the entry permits NO parameters
    at all (empty dict), not "anything" — see _matches_allowed_action's
    docstring for why this default matters.
    Returns None for anything malformed (extra tokens beyond one, a token
    not starting with "params:", an empty key/pattern either side of `=`,
    or a pattern that isn't a valid regex), signalling the caller to deny
    outright rather than guess an interpretation.
    """
    if not extra_tokens:
        return {}
    if len(extra_tokens) > 1 or not extra_tokens[0].startswith(_PARAMS_CLAUSE_PREFIX):
        return None
    keys_part = extra_tokens[0][len(_PARAMS_CLAUSE_PREFIX) :]
    allowed: Dict[str, Optional[re.Pattern]] = {}
    for raw in _split_top_level_commas(keys_part):
        if not raw:
            continue
        if "=" in raw:
            key, pattern_text = raw.split("=", 1)
            if not key or not pattern_text:
                return None
            try:
                allowed[key] = re.compile(pattern_text)
            except re.error:
                return None
        else:
            allowed[raw] = None
    return allowed


def _matches_allowed_action(action: ActionSpec, allowed_action: str) -> bool:
    # allowed_action MUST be a full URL with scheme+host, in the form
    # "METHOD https://host/path/template/{param}" — NOT just a path. Matching
    # only the path (ignoring host) would let an action target any host as
    # long as the path matches — equivalent to a scope-escape/SSRF
    # vulnerability inside Policy Service itself (found and fixed — see
    # tests/test_policy.py).
    #
    # An optional 3rd token, "params:key1,key2", declares which
    # ActionSpec.parameters keys this entry permits. Real gap found via
    # full-codebase review: parameters were never checked at all — an action
    # matching the URL/method could carry ANY key/value in its body or query
    # string (e.g. {"debug_bypass_auth": "1"}), since ActionSpec.parameters
    # is built directly from unvalidated LLM JSON (exploit_agent/agent.py)
    # and sent as-is by evidence_harness/harness.py. Omitting the clause
    # means the entry permits an EMPTY parameters dict only — not "anything"
    # — matching this project's deny-by-default default in every other gate.
    #
    # A key can optionally be paired with a value pattern, "key=regex" (e.g.
    # "params:userId=^\d+$"), checked against str(value) with fullmatch.
    # Real gap found via independent review of the value channel itself:
    # checking only parameter NAMES still let ANY value through for an
    # already-allowed key — an LLM-authored plan could put a completely
    # different identity's id, an injection payload, or control characters
    # into a parameter whose name happens to be on the allowlist. A
    # name-only key (no "=regex") keeps the previous behaviour (any value
    # permitted) — this is opt-in stricter checking, not a breaking change
    # to existing allowlist strings.
    tokens = allowed_action.split()
    if len(tokens) < 2:
        return False
    method, template = tokens[0], tokens[1]
    allowed_params = _parse_allowed_params(tokens[2:])
    if allowed_params is None:
        return False
    if action.method.upper() != method.upper():
        return False
    if not set(action.parameters.keys()) <= set(allowed_params.keys()):
        return False
    for key, value_pattern in allowed_params.items():
        if value_pattern is None or key not in action.parameters:
            continue
        raw_value = action.parameters[key]
        # A JSON null stringifies to the literal text "None", which can
        # satisfy an otherwise-reasonable pattern like "^[A-Za-z]+$" — a
        # real footgun an independent review found: an operator declaring
        # a value pattern for a string field would not expect null to pass
        # it. A declared pattern is a promise that the value is real data
        # of a specific shape — null is never that, regardless of pattern.
        if raw_value is None or not value_pattern.fullmatch(str(raw_value)):
            return False

    action_url = urlsplit(action.target)
    template_url = urlsplit(template)

    if action_url.query:
        # Real bypass found via review: the params check above only looks at
        # action.parameters — it says nothing about a query string smuggled
        # directly inside action.target itself (e.g.
        # "https://host/api/objects/123?debug_bypass_auth=1"), which
        # evidence_harness/harness.py sends to the real target completely
        # unfiltered (httpx keeps a URL's own query string when params=None).
        # Since ActionSpec.parameters is the one designated, checked channel
        # for extra data, a target that already carries its own query string
        # is always denied — no legitimate action needs both.
        return False
    if not template_url.netloc:
        # Allowlist entry missing a host — treat as misconfiguration and deny
        # outright, instead of silently falling back to matching path only
        # (that's exactly the vulnerability that was fixed).
        return False
    if action_url.scheme.lower() != template_url.scheme.lower():
        # .lower() on both sides — real nitpick found via independent
        # review: URL schemes are case-insensitive per RFC 3986, but this
        # compared them case-sensitively while netloc (below) was already
        # lowercased. Fails SAFE as-is (a legitimate "HTTPS://..." action
        # was wrongly DENIED, not wrongly allowed), so not a bypass, but
        # worth fixing for correctness rather than leaving an inconsistency.
        return False
    if action_url.netloc.lower() != template_url.netloc.lower():
        return False

    decoded_path = _decode_path_safely(action_url.path)
    if decoded_path is None:
        return False
    return bool(_path_template_to_regex(template_url.path).fullmatch(decoded_path))


def is_allowed(
    action: ActionSpec, authorization: Authorization, now: Optional[datetime] = None
) -> PolicyDecision:
    """Policy Service — weekly plan W5: `is_allowed(action) -> PolicyDecision`.

    Does not check the action-count cap (that's Cost Service, not built in
    this pass) or whether Execution Release has been granted (that's the
    Execute step, not reached in W5) — only checks what's within scope of
    the allowlist/time window.
    """
    now = now or datetime.now(timezone.utc)
    method = action.method.upper()

    if method in FORBIDDEN_METHODS:
        return PolicyDecision(
            allowed=False,
            reason=(
                f"HTTP method '{method}' không bao giờ được phép trong allowlist — "
                "xóa/sửa dữ liệu hiện hữu nằm ngoài phạm vi pilot (SPEC §4.2)."
            ),
        )

    if authorization.revoked:
        return PolicyDecision(allowed=False, reason="Authorization đã bị thu hồi (revoked=true).")

    if authorization.expiry is not None and now > authorization.expiry:
        return PolicyDecision(
            allowed=False, reason=f"Authorization đã hết hạn lúc {authorization.expiry.isoformat()}."
        )

    if authorization.window_start is not None and now < authorization.window_start:
        return PolicyDecision(
            allowed=False,
            reason=f"Chưa tới cửa sổ thời gian được phép (bắt đầu {authorization.window_start.isoformat()}).",
        )

    if authorization.window_end is not None and now > authorization.window_end:
        return PolicyDecision(
            allowed=False,
            reason=f"Đã qua cửa sổ thời gian được phép (kết thúc {authorization.window_end.isoformat()}).",
        )

    for allowed_action in authorization.allowed_actions:
        if _matches_allowed_action(action, allowed_action):
            return PolicyDecision(allowed=True, reason=f"Khớp allowlist entry '{allowed_action}'.")

    return PolicyDecision(
        allowed=False,
        reason=(
            f"'{method} {action.target}' không khớp bất kỳ entry nào trong allowlist "
            f"({len(authorization.allowed_actions)} entry đã cấp) — kiểm tra cả host lẫn path."
        ),
    )
