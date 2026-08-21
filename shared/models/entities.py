from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class Organization(BaseModel):
    id: str
    name: str


class Project(BaseModel):
    id: str
    organization_id: str
    name: str


class System(BaseModel):
    id: str
    project_id: str
    name: str


class Target(BaseModel):
    id: str
    system_id: str
    name: str


class TargetRevision(BaseModel):
    id: str
    target_id: str
    identifier: str
    pinned_at: datetime


class AuthorizationLayer(str, Enum):
    PROJECT_APPROVAL = "project_approval"
    TARGET_AUTHORIZATION = "target_authorization"
    EXECUTION_RELEASE = "execution_release"


class Authorization(BaseModel):
    id: str
    layer: AuthorizationLayer
    approved_by: str
    approved_at: datetime
    target_id: Optional[str] = None
    target_revision_id: Optional[str] = None
    identity: Optional[str] = None
    allowed_actions: List[str] = Field(default_factory=list)
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    stop_work_contact: Optional[str] = None
    cleanup_plan: Optional[str] = None
    expiry: Optional[datetime] = None
    revoked: bool = False

    @field_validator("window_start", "window_end", "expiry")
    @classmethod
    def _require_timezone_aware(cls, value: Optional[datetime]) -> Optional[datetime]:
        """shared/policy.py::is_allowed always compares these fields against
        datetime.now(timezone.utc), so a timezone-NAIVE value here would
        crash that comparison with an uncaught TypeError instead of a clean
        deny. Currently unreachable through this codebase's own call sites
        (the CLI only ever sets approved_at via datetime.now(timezone.utc)
        and never sets these 3 fields), but a landmine for the day real
        Gate 2/3 data loads from an operator-authored file or API, where an
        omitted UTC offset is a very natural mistake. Rejects outright
        rather than silently assuming UTC — guessing wrong here means an
        authorization window could look valid past its real expiry, or
        expire early, which is exactly the kind of silent misinterpretation
        this project's controls are designed to never allow.
        """
        if value is not None and value.tzinfo is None:
            raise ValueError(
                "datetime phải có timezone (vd offset '+00:00' hoặc 'Z') — thiếu timezone dễ bị "
                "hiểu nhầm giữa giờ địa phương và UTC, và is_allowed() luôn so sánh bằng "
                "datetime.now(timezone.utc)."
            )
        return value
