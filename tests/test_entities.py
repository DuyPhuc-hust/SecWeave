from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from shared.models.entities import (
    Authorization,
    AuthorizationLayer,
    Organization,
    Project,
    System,
    Target,
    TargetRevision,
)


def test_organization_valid():
    org = Organization(id="org_1", name="NTQ")
    assert org.id == "org_1"


def test_organization_missing_field():
    with pytest.raises(ValidationError):
        Organization(id="org_1")


def test_project_valid():
    project = Project(id="proj_1", organization_id="org_1", name="CSP")
    assert project.organization_id == "org_1"


def test_project_missing_field():
    with pytest.raises(ValidationError):
        Project(id="proj_1", name="CSP")


def test_system_valid():
    system = System(id="sys_1", project_id="proj_1", name="NxKeeper")
    assert system.name == "NxKeeper"


def test_system_missing_field():
    with pytest.raises(ValidationError):
        System(id="sys_1", name="NxKeeper")


def test_target_valid():
    target = Target(id="tgt_1", system_id="sys_1", name="NxKeeper staging")
    assert target.system_id == "sys_1"


def test_target_missing_field():
    with pytest.raises(ValidationError):
        Target(id="tgt_1")


def test_target_revision_valid():
    revision = TargetRevision(
        id="rev_1",
        target_id="tgt_1",
        identifier="a1b2c3d",
        pinned_at=datetime.now(timezone.utc),
    )
    assert revision.identifier == "a1b2c3d"


def test_target_revision_missing_field():
    with pytest.raises(ValidationError):
        TargetRevision(id="rev_1", target_id="tgt_1")


def test_authorization_valid_project_approval():
    auth = Authorization(
        id="auth_1",
        layer=AuthorizationLayer.PROJECT_APPROVAL,
        approved_by="sponsor",
        approved_at=datetime.now(timezone.utc),
    )
    assert auth.layer == AuthorizationLayer.PROJECT_APPROVAL
    assert auth.target_id is None


def test_authorization_valid_target_authorization():
    auth = Authorization(
        id="auth_2",
        layer=AuthorizationLayer.TARGET_AUTHORIZATION,
        approved_by="owner",
        approved_at=datetime.now(timezone.utc),
        target_id="tgt_1",
        identity="test-identity-1",
        allowed_actions=["GET https://staging.example.com/api/objects/{id}"],
    )
    assert auth.target_id == "tgt_1"
    assert "GET https://staging.example.com/api/objects/{id}" in auth.allowed_actions


def test_authorization_missing_field():
    with pytest.raises(ValidationError):
        Authorization(id="auth_3", layer=AuthorizationLayer.EXECUTION_RELEASE)


def test_authorization_rejects_timezone_naive_expiry():
    # Real gap found via independent review: a naive datetime used to be
    # accepted silently here, then made shared/policy.py::is_allowed crash
    # with an uncaught TypeError (comparing offset-naive vs offset-aware)
    # instead of a clean deny — is_allowed() always compares against
    # datetime.now(timezone.utc).
    with pytest.raises(ValidationError):
        Authorization(
            id="auth_4",
            layer=AuthorizationLayer.TARGET_AUTHORIZATION,
            approved_by="owner",
            approved_at=datetime.now(timezone.utc),
            expiry=datetime(2026, 8, 20, 10, 0, 0),  # no tzinfo
        )


@pytest.mark.parametrize("field", ["window_start", "window_end", "expiry"])
def test_authorization_rejects_timezone_naive_on_every_datetime_field(field):
    with pytest.raises(ValidationError):
        Authorization(
            id="auth_5",
            layer=AuthorizationLayer.TARGET_AUTHORIZATION,
            approved_by="owner",
            approved_at=datetime.now(timezone.utc),
            **{field: datetime(2026, 8, 20, 10, 0, 0)},
        )


def test_authorization_accepts_timezone_aware_expiry():
    auth = Authorization(
        id="auth_6",
        layer=AuthorizationLayer.TARGET_AUTHORIZATION,
        approved_by="owner",
        approved_at=datetime.now(timezone.utc),
        expiry=datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc),
    )
    assert auth.expiry.tzinfo is not None
