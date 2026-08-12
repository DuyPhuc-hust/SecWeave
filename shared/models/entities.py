from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


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
