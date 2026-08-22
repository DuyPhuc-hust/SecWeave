import re
import unicodedata
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
    path template. Matching the RAW (still percent-encoded) path would let
    a segment like "%2e%2e%2fadmin" satisfy a "{id}" placeholder's `[^/]+`
    regex (no literal "/" in the raw text) — but httpx sends the raw
    encoded path unchanged on the wire, and the real target (or any proxy
    in front of it) may decode+normalize it into "/api/objects/../admin"
    -> "/api/admin", escaping the allowlisted scope entirely. Returns None
    (caller must deny) if decoding (up to _MAX_DECODE_PASSES rounds, to
    also catch double-encoding like "%252e%252e%252fadmin") reveals a "/"
    that wasn't literally present in the ORIGINAL raw path (an encoded
    slash would change the segment structure the template was matched
    against), a backslash (the separator a Windows/IIS-style backend would
    treat as a path boundary), or a "."/".." segment (never legitimate for
    a single {id}-style path segment). Denies outright if decoding hasn't
    stabilized within _MAX_DECODE_PASSES rounds, rather than risk matching
    against a still-partially-encoded string.

    Also denies if Unicode NFKC normalization of the decoded path reveals a
    "/", "\\", or "."/".." segment not present in the un-normalized form —
    a compatibility-equivalent character such as U+FF0F FULLWIDTH SOLIDUS
    ("／") contains no literal ASCII "/"/"."/"\\", so the checks above pass
    it through unchanged as one opaque {id}-style segment — but IIS/
    ASP.NET's "best-fit" mapping and any NFKC-normalizing backend collapse
    it back to a literal "/" before routing, letting "1／..／admin" reach
    the target as "1/../admin". Matching still happens against the
    UN-normalized `decoded` (what actually goes out on the wire via httpx)
    — normalization here is only used to DETECT a lookalike separator,
    never to rewrite what's sent.
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
    normalized = unicodedata.normalize("NFKC", decoded)
    if normalized.count("/") != decoded.count("/"):
        return None
    if "\\" in normalized:
        return None
    if any(segment in (".", "..") for segment in normalized.split("/")):
        return None
    return decoded


_PARAMS_CLAUSE_PREFIX = "params:"


def _split_top_level_commas(text: str) -> List[str]:
    """Splits on commas that aren't nested inside {}, (), or [] — so a
    bounded-repetition quantifier like the "2,4" in "^a{2,4}$" (the single
    most natural way to write "N-digit id") survives intact instead of
    being cut in half. A naive text.split(",") would silently mangle any
    key=regex pair using such a quantifier into a near-useless truncated
    pattern (`^a{2`) AND create a bogus extra allowlist key from the
    leftover text (`4}$`, mapped to "no value constraint") — corrupting
    the operator's allowlist without ever raising an error.
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
    a pattern that isn't a valid regex, or the SAME key named more than
    once — e.g. "id=^\\d+$,id" naming `id` both constrained and name-only)
    signalling the caller to deny outright rather than guess an
    interpretation. A duplicate key is never resolved by "last one wins":
    that would let a later, unconstrained (or more permissive) occurrence
    silently erase an earlier, deliberately narrow value pattern — exactly
    the kind of ambiguous allowlist text this function's whole design
    refuses to guess through everywhere else.
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
        else:
            key, pattern_text = raw, None
        if key in allowed:
            return None
        if pattern_text is None:
            allowed[key] = None
        else:
            try:
                allowed[key] = re.compile(pattern_text)
            except re.error:
                return None
    return allowed


def _matches_allowed_action(action: ActionSpec, allowed_action: str) -> bool:
    # allowed_action MUST be a full URL with scheme+host, in the form
    # "METHOD https://host/path/template/{param}" — NOT just a path.
    # Matching only the path (ignoring host) would let an action target any
    # host as long as the path matches — equivalent to a scope-escape/SSRF
    # vulnerability inside Policy Service itself (see tests/test_policy.py).
    #
    # An optional 3rd token, "params:key1,key2", declares which
    # ActionSpec.parameters keys this entry permits — without it, an action
    # matching the URL/method could carry ANY key/value in its body or
    # query string (e.g. {"debug_bypass_auth": "1"}), since
    # ActionSpec.parameters is built directly from unvalidated LLM JSON and
    # sent as-is by evidence_harness/harness.py. Omitting the clause means
    # the entry permits an EMPTY parameters dict only — not "anything" —
    # matching this project's deny-by-default default everywhere else.
    #
    # A key can optionally be paired with a value pattern, "key=regex" (e.g.
    # "params:userId=^\d+$"), checked against str(value) with fullmatch —
    # checking only parameter NAMES would still let ANY value through for
    # an already-allowed key (a different identity's id, an injection
    # payload, control characters). A name-only key (no "=regex") keeps the
    # simpler behaviour (any value permitted) — opt-in stricter checking,
    # not a breaking change to existing allowlist strings.
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
        # satisfy an otherwise-reasonable pattern like "^[A-Za-z]+$" — an
        # operator declaring a value pattern for a string field would not
        # expect null to pass it. A declared pattern is a promise that the
        # value is real data of a specific shape — null is never that.
        if raw_value is None or not value_pattern.fullmatch(str(raw_value)):
            return False

    action_url = urlsplit(action.target)
    template_url = urlsplit(template)

    if action_url.query:
        # The params check above only looks at action.parameters — a query
        # string smuggled directly inside action.target itself (e.g.
        # "https://host/api/objects/123?debug_bypass_auth=1") is sent to
        # the real target completely unfiltered by evidence_harness/
        # harness.py (httpx keeps a URL's own query string when
        # params=None). Since ActionSpec.parameters is the one designated,
        # checked channel for extra data, a target that already carries
        # its own query string is always denied — no legitimate action
        # needs both.
        return False
    if not template_url.netloc:
        # Allowlist entry missing a host — treat as misconfiguration and deny
        # outright, instead of silently falling back to matching path only.
        return False
    if action_url.scheme.lower() != template_url.scheme.lower():
        # .lower() on both sides — URL schemes are case-insensitive per
        # RFC 3986, and netloc (below) is already compared lowercased too.
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
