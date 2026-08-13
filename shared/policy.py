import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

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


def _matches_allowed_action(action: ActionSpec, allowed_action: str) -> bool:
    # allowed_action MUST be a full URL with scheme+host, in the form
    # "METHOD https://host/path/template/{param}" — NOT just a path. Matching
    # only the path (ignoring host) would let an action target any host as
    # long as the path matches — equivalent to a scope-escape/SSRF
    # vulnerability inside Policy Service itself (found and fixed — see
    # tests/test_policy.py).
    try:
        method, template = allowed_action.split(maxsplit=1)
    except ValueError:
        return False
    if action.method.upper() != method.upper():
        return False

    action_url = urlsplit(action.target)
    template_url = urlsplit(template)

    if not template_url.netloc:
        # Allowlist entry missing a host — treat as misconfiguration and deny
        # outright, instead of silently falling back to matching path only
        # (that's exactly the vulnerability that was fixed).
        return False
    if action_url.scheme != template_url.scheme:
        return False
    if action_url.netloc.lower() != template_url.netloc.lower():
        return False

    return bool(_path_template_to_regex(template_url.path).fullmatch(action_url.path))


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
