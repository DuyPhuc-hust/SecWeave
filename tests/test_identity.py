import os

import pytest

from shared.identity import get_execution_identity
from tests.factories import sample_authorization


def test_returns_identity_from_authorization():
    authorization = sample_authorization(identity="test-identity-1")
    assert get_execution_identity(authorization) == "test-identity-1"


def test_raises_when_authorization_has_no_identity():
    authorization = sample_authorization(identity=None)
    with pytest.raises(ValueError, match="chưa có identity"):
        get_execution_identity(authorization)


def test_never_reads_from_environment_variables(monkeypatch):
    # Xóa sạch mọi biến môi trường rồi vẫn phải trả đúng identity từ
    # Authorization — chứng minh hàm này không phụ thuộc os.environ dưới bất
    # kỳ hình thức nào, đúng yêu cầu "không đọc tài khoản cá nhân" của W5.
    for key in list(os.environ.keys()):
        monkeypatch.delenv(key, raising=False)
    authorization = sample_authorization(identity="test-identity-1")
    assert get_execution_identity(authorization) == "test-identity-1"


def test_does_not_fall_back_to_approved_by_field():
    # approved_by ("owner", tài khoản người phê duyệt) khác hẳn identity thực
    # thi — không được lẫn lộn 2 khái niệm này khi identity bị thiếu.
    authorization = sample_authorization(identity=None, approved_by="owner-personal-account")
    with pytest.raises(ValueError):
        get_execution_identity(authorization)
