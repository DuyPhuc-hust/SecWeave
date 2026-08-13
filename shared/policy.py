import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

from shared.models.action import ActionSpec, PolicyDecision
from shared.models.entities import Authorization

# SPEC §4.2: "hành động xóa, sửa dữ liệu hiện hữu, đổi cấu hình, tác động khả
# dụng dịch vụ, hoặc quét mạng diện rộng ... không được đưa vào allowlist dưới
# bất kỳ hình thức nào" — chặn cứng ở đây, không phụ thuộc nội dung allowlist
# (allowlist cấu hình sai cũng không thể mở khóa các method này).
FORBIDDEN_METHODS = {"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"}


def _path_template_to_regex(template: str) -> re.Pattern:
    # "/api/objects/{id}" -> mỗi {..} khớp đúng 1 path segment (không khớp "/").
    # Không tự thêm ^/$ — dùng fullmatch() ở nơi gọi thay vì match() với "$",
    # để không phụ thuộc ngữ nghĩa tinh vi của "$" (khớp cả trước 1 newline
    # cuối chuỗi) — urlsplit() đã tự lọc control character nên chưa thấy khai
    # thác được qua đường này, nhưng fullmatch() vẫn đơn giản và chắc chắn hơn.
    segments = re.split(r"(\{[^/{}]+\})", template)
    regex_parts = [
        r"[^/]+" if seg.startswith("{") and seg.endswith("}") else re.escape(seg)
        for seg in segments
    ]
    return re.compile("".join(regex_parts))


def _matches_allowed_action(action: ActionSpec, allowed_action: str) -> bool:
    # allowed_action BẮT BUỘC là URL đầy đủ có scheme+host, dạng
    # "METHOD https://host/path/template/{param}" — KHÔNG chỉ có path. Chỉ so
    # path (bỏ qua host) sẽ cho phép action nhắm bất kỳ host nào miễn path
    # khớp, tương đương lỗ hổng scope-escape/SSRF ngay trong chính Policy
    # Service (đã phát hiện và vá — xem tests/test_policy.py).
    try:
        method, template = allowed_action.split(maxsplit=1)
    except ValueError:
        return False
    if action.method.upper() != method.upper():
        return False

    action_url = urlsplit(action.target)
    template_url = urlsplit(template)

    if not template_url.netloc:
        # Allowlist entry thiếu host — coi là cấu hình sai, từ chối thẳng
        # thay vì âm thầm chỉ so path (đó chính là lỗ hổng đã vá).
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

    Không kiểm tra cap số lượng hành động (thuộc Cost Service, chưa xây trong
    lượt này) hay việc Execution Release đã cấp chưa (thuộc bước Execute, chưa
    tới trong W5) — chỉ kiểm những gì thuộc phạm vi allowlist/thời hạn.
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
