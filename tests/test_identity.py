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
    # Wipes every environment variable and confirms the function still
    # returns the right identity from Authorization — proving it doesn't
    # depend on os.environ in any way, per W5's "must not read a personal
    # account" requirement.
    for key in list(os.environ.keys()):
        monkeypatch.delenv(key, raising=False)
    authorization = sample_authorization(identity="test-identity-1")
    assert get_execution_identity(authorization) == "test-identity-1"


def test_does_not_fall_back_to_approved_by_field():
    # approved_by ("owner", the approver's account) is a completely
    # different concept from the execution identity — these two must not be
    # conflated when identity is missing.
    authorization = sample_authorization(identity=None, approved_by="owner-personal-account")
    with pytest.raises(ValueError):
        get_execution_identity(authorization)
