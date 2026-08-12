from datetime import datetime
from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, Field


class ScopeStatus(str, Enum):
    TARGET = "TARGET"
    AUTHORIZED_DEPENDENCY = "AUTHORIZED_DEPENDENCY"
    OBSERVE_ONLY = "OBSERVE_ONLY"
    CONTEXT_ONLY = "CONTEXT_ONLY"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"


class SignalType(str, Enum):
    SAST = "SAST"
    SCA = "SCA"
    CONTAINER = "CONTAINER"
    DAST = "DAST"
    HUMAN = "HUMAN"


class SignalCoverage(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class NormalizedSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SignalSource(BaseModel):
    tool: str
    tool_version: str
    type: SignalType
    coverage: SignalCoverage


class RuleInfo(BaseModel):
    id: str
    name: str
    cwe: List[str] = Field(default_factory=list)
    owasp_category: Optional[str] = None


class SeverityInfo(BaseModel):
    raw: str
    normalized: NormalizedSeverity


class SastLocation(BaseModel):
    file_path: str
    start_line: int
    end_line: int


class ScaLocation(BaseModel):
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    artifact_ref: str


class DastLocation(BaseModel):
    url: str
    http_method: str
    parameter: Optional[str] = None


class TargetHint(BaseModel):
    system_hint: Optional[str] = None
    component_hint: Optional[str] = None


class RawReference(BaseModel):
    storage_path: str
    hash: str


class NormalizedSignal(BaseModel):
    signal_id: str
    source: SignalSource
    rule: RuleInfo
    severity: SeverityInfo
    location: Union[SastLocation, ScaLocation, DastLocation]
    signal_context: str
    target_hint: TargetHint
    ingested_at: datetime
    raw_reference: RawReference
