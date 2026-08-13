from datetime import datetime, timedelta, timezone

import pytest

from shared.models.action import ActionSpec, ActionType
from shared.policy import is_allowed
from tests.factories import sample_authorization

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=timezone.utc)

ALLOWED_ENTRY = "GET https://staging.example.com/api/objects/{id}"


def _action(**overrides) -> ActionSpec:
    defaults = dict(
        type=ActionType.READ_ONLY,
        method="GET",
        target="https://staging.example.com/api/objects/42",
        description="Read object 42 as a non-owner identity.",
    )
    defaults.update(overrides)
    return ActionSpec(**defaults)


def test_matching_action_is_allowed():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is True
    assert ALLOWED_ENTRY in decision.reason


def test_wrong_method_is_denied():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(method="POST", type=ActionType.TEST_DATA_CREATION)
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_endpoint_outside_allowlist_is_denied():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(target="https://staging.example.com/api/admin/users")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False
    assert "không khớp" in decision.reason


def test_same_path_on_different_host_is_denied():
    # Regression cho lỗ hổng đã vá: Policy Service trước đây chỉ so path, bỏ
    # qua host — 1 action nhắm vào host bất kỳ (kể cả kẻ tấn công kiểm soát)
    # vẫn "khớp" allowlist miễn path đúng dạng. Path đúng, host sai PHẢI bị từ chối.
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(target="https://evil-attacker-controlled.com/api/objects/42")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_same_path_different_scheme_is_denied():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(target="http://staging.example.com/api/objects/42")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_allowlist_entry_missing_host_never_matches():
    # Entry cấu hình sai (thiếu host, dạng cũ chỉ có path) phải bị từ chối
    # thẳng, không được âm thầm rơi về so path — đó chính là lỗ hổng đã vá.
    authorization = sample_authorization(allowed_actions=["GET /api/objects/{id}"])
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is False


@pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH", "delete", "put"])
def test_destructive_methods_are_always_denied_regardless_of_allowlist(method):
    # Allowlist "cho phép" endpoint này bằng mọi method — nhưng method phá hoại
    # vẫn phải bị chặn cứng, allowlist cấu hình sai cũng không mở khóa được.
    authorization = sample_authorization(
        allowed_actions=[f"{method.upper()} https://staging.example.com/api/objects/{{id}}"]
    )
    action = _action(method=method, type=ActionType.TEST_DATA_CREATION)
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False
    assert "không bao giờ được phép" in decision.reason


def test_revoked_authorization_is_denied():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY], revoked=True)
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is False
    assert "thu hồi" in decision.reason


def test_expired_authorization_is_denied():
    authorization = sample_authorization(
        allowed_actions=[ALLOWED_ENTRY], expiry=NOW - timedelta(days=1)
    )
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is False
    assert "hết hạn" in decision.reason


def test_action_before_window_start_is_denied():
    authorization = sample_authorization(
        allowed_actions=[ALLOWED_ENTRY], window_start=NOW + timedelta(hours=1)
    )
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is False
    assert "Chưa tới cửa sổ" in decision.reason


def test_action_after_window_end_is_denied():
    authorization = sample_authorization(
        allowed_actions=[ALLOWED_ENTRY], window_end=NOW - timedelta(hours=1)
    )
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is False
    assert "Đã qua cửa sổ" in decision.reason


def test_action_within_window_is_allowed():
    authorization = sample_authorization(
        allowed_actions=[ALLOWED_ENTRY],
        window_start=NOW - timedelta(hours=1),
        window_end=NOW + timedelta(hours=1),
    )
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is True


def test_path_template_does_not_match_across_extra_segments():
    # "/api/objects/{id}" chỉ khớp đúng 1 segment — không được khớp
    # "/api/objects/42/secret" (path traversal ngoài ý định allowlist).
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(target="https://staging.example.com/api/objects/42/secret")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_matches_correct_entry_among_multiple_allowed_actions():
    authorization = sample_authorization(
        allowed_actions=[ALLOWED_ENTRY, "POST https://staging.example.com/api/objects"]
    )
    decision = is_allowed(
        _action(
            method="POST",
            type=ActionType.TEST_DATA_CREATION,
            target="https://staging.example.com/api/objects",
        ),
        authorization,
        now=NOW,
    )
    assert decision.allowed is True
    assert "POST https://staging.example.com/api/objects" in decision.reason
