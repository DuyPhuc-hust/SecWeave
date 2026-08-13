from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator


class ActionType(str, Enum):
    """SPEC §4.2 — only 2 action types are considered allowable in the pilot.

    Actions that delete/modify existing data, change configuration, impact
    availability, or perform broad-scope scanning have NO corresponding enum
    value — an ActionType of those kinds cannot be constructed, even for
    testing purposes.
    """

    READ_ONLY = "read_only"
    TEST_DATA_CREATION = "test_data_creation"


class ActionSpec(BaseModel):
    """A planned action within an ActionPlan. Field name matches weekly plan
    W5: `is_allowed(action: ActionSpec) -> PolicyDecision`.

    This model ONLY holds data — it does not itself block a dangerous method
    (e.g. DELETE). That's Policy Service's job (shared/policy.py), so an
    adversarial test can construct exactly the kind of violating ActionSpec
    it wants and confirm is_allowed() rejects it, instead of Pydantic
    blocking it before it ever reaches Policy Service.
    """

    type: ActionType
    method: str
    target: str
    description: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ActionPlan(BaseModel):
    hypothesis_id: str
    actions: List[ActionSpec]


class ActionPlanStatus(str, Enum):
    PLANNED = "planned"
    NOT_PLANNABLE = "not_plannable"


class ActionPlanResult(BaseModel):
    """Result of build_plan — mirrors HypothesisResult: the engine can return
    either a real plan, or a refusal with a reason (when the Hypothesis isn't
    concrete enough to build an action plan from) — no ambiguous state in
    between.
    """

    status: ActionPlanStatus
    plan: Optional[ActionPlan] = None
    reason: Optional[str] = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "ActionPlanResult":
        if self.status == ActionPlanStatus.PLANNED and self.plan is None:
            raise ValueError("status=planned requires a plan")
        if self.status == ActionPlanStatus.NOT_PLANNABLE and not self.reason:
            raise ValueError("status=not_plannable requires a reason")
        return self


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str


class ActionCheckResult(BaseModel):
    action: ActionSpec
    decision: PolicyDecision


class PlanCheckResult(BaseModel):
    """Result of checking an entire ActionPlan against the allowlist — deny-
    by-default: approved is True only when ALL actions pass; failing actions
    are never silently dropped in order to treat the rest as approved (per
    weekly plan W5's required principle).
    """

    approved: bool
    checks: List[ActionCheckResult]


class CostDecision(BaseModel):
    """Result of Cost Service (skeleton) — weekly plan W5: only counts the
    PLANNED actions in a plan against a cap; doesn't yet count actually
    executed actions (needs a real Evidence Harness to execute them, coming
    the following week)."""

    allowed: bool
    reason: str
    planned_action_count: int
    cap: int


class PlanReviewResult(BaseModel):
    """The single gate to use before treating an ActionPlan as safe to
    proceed with — combines both the allowlist check (PlanCheckResult) and
    the cost-cap check (CostDecision) into one boolean, so nobody accidentally
    calls just one of the two and treats the plan as fully approved.
    """

    approved: bool
    plan_check: PlanCheckResult
    cost_check: CostDecision
