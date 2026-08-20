from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator

from shared.id_generator import generate_id
from shared.models.observation import ObservationRole


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

    # Stable identifier for this one action within a plan. Added when Evidence
    # Harness needed something to put in NormalizedObservation.action_ref
    # (shared/models/observation.py) — auto-generated so existing call sites
    # that don't pass it keep working unchanged.
    action_id: str = Field(default_factory=lambda: generate_id("act"))
    type: ActionType
    method: str
    target: str
    description: str
    parameters: Dict[str, Any] = Field(default_factory=dict)

    # Which of the 3 required predicate groups (SPEC §4.4.1) this action is
    # meant to serve as evidence for, or SETUP if it's neither (e.g. a login
    # / bait-data-seeding step) — assigned when the plan is designed, same
    # reasoning as ObservationRole's own docstring. Defaults to MAIN so every
    # existing single-role plan (the only kind Exploit Agent could produce
    # before this field existed) keeps meaning exactly what it always did —
    # this field only lets a plan OPT INTO tagging a real 3-role scenario,
    # it never changes behavior for a plan that doesn't use it.
    role: ObservationRole = ObservationRole.MAIN

    # An optional stable label this action's REAL response can be
    # referenced by from a LATER action in the same plan (e.g. a
    # test_data_creation action that seeds a resource and needs its
    # server-assigned ID relayed into a later action's target/parameters).
    # Assigned by Exploit Agent when it designs the plan — see cli.py's
    # `{{FROM_STEP:<step_id>:<json.path>}}` placeholder (resolved at
    # execution time, after step_id's action actually ran, never guessed
    # or invented by the LLM). None (the default) means this action's
    # response is never referenced by anything later — the overwhelming
    # majority of actions.
    step_id: Optional[str] = None


class ActionPlan(BaseModel):
    hypothesis_id: str
    # min_length=1 — an empty plan would make check_plan()'s all(...) over
    # zero checks vacuously True ("approved"), and
    # check_planned_action_cap's count=0 is trivially within any cap —
    # "approved, 0 actions" is never a meaningful state to report as safe,
    # same "an ambiguous/empty state must never look identical to a
    # verified-safe one" reasoning as PlanCheckResult/CostDecision's own
    # validators.
    actions: List[ActionSpec] = Field(min_length=1)


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
        if self.status == ActionPlanStatus.NOT_PLANNABLE and self.plan is not None:
            # A future caller reading `.plan` without checking `.status`
            # first must never find a real plan the engine refused to stand
            # behind.
            raise ValueError("status=not_plannable không được kèm theo plan")
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
    # min_length=1 — without it, `PlanCheckResult(approved=True, checks=[])`
    # would construct cleanly, since `all(... for check in [])` is
    # vacuously True — "approved, 0 checks" would look identical to a
    # genuinely-reviewed plan. Same
    # reasoning as ActionPlan.actions's own min_length=1 (see its
    # comment) — currently unreachable through check_plan()'s one real
    # call site (it builds `checks` 1:1 from ActionPlan.actions, which
    # already can't be empty), but this model is a standalone,
    # independently-constructible result (a test fixture, a JSON reload,
    # a future second call site) and should not rely solely on that one
    # caller happening to never pass an empty list.
    checks: List[ActionCheckResult] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_consistency(self) -> "PlanCheckResult":
        # `approved` must never be settable independently of `checks` — a
        # safety-critical boolean out of sync with the data it summarizes.
        all_allowed = all(check.decision.allowed for check in self.checks)
        if self.approved != all_allowed:
            raise ValueError(
                "approved phải khớp đúng: True chỉ khi TẤT CẢ checks đều allowed=True — "
                "không được set approved khác với thực tế từng action."
            )
        return self


class CostDecision(BaseModel):
    """Result of Cost Service (skeleton) — weekly plan W5: only counts the
    PLANNED actions in a plan against a cap; doesn't yet count actually
    executed actions (needs a real Evidence Harness to execute them, coming
    the following week)."""

    allowed: bool
    reason: str
    planned_action_count: int
    cap: int

    @model_validator(mode="after")
    def _check_consistency(self) -> "CostDecision":
        expected_allowed = self.planned_action_count <= self.cap
        if self.allowed != expected_allowed:
            raise ValueError(
                f"allowed phải khớp đúng planned_action_count ({self.planned_action_count}) so với "
                f"cap ({self.cap}) — không được set allowed khác với so sánh thực tế."
            )
        return self


class RuntimeCostDecision(BaseModel):
    """Result of CostService.record_action() (shared/cost.py) — the RUNTIME
    cost-cap gate, enforced during an actual active run (weekly plan
    Tuần 6: "đếm hành động thực tế... tự động trigger STOPPED khi chạm
    cap"). Distinct from CostDecision above, which only checks a PLANNED
    count before execution ever starts — one CostService.record_action()
    call happens per real EvidenceHarness.capture() ATTEMPT (success or
    failure at the HTTP level both count — an attempted request against
    the target already consumed real budget regardless of the response it
    got back).

    `executed_action_count` is the count of actions ALREADY recorded
    BEFORE this one is considered (a plain descriptive fact, same
    reasoning as CostDecision.planned_action_count) — this action is
    `allowed` exactly when that count is still under `cap`.
    """

    allowed: bool
    reason: str
    executed_action_count: int
    cap: int

    @model_validator(mode="after")
    def _check_consistency(self) -> "RuntimeCostDecision":
        expected_allowed = self.executed_action_count < self.cap
        if self.allowed != expected_allowed:
            raise ValueError(
                f"allowed phải khớp đúng executed_action_count ({self.executed_action_count}) so "
                f"với cap ({self.cap}) — không được set allowed khác với so sánh thực tế."
            )
        return self


class PlanReviewResult(BaseModel):
    """The single gate to use before treating an ActionPlan as safe to
    proceed with — combines both the allowlist check (PlanCheckResult) and
    the cost-cap check (CostDecision) into one boolean, so nobody accidentally
    calls just one of the two and treats the plan as fully approved.
    """

    approved: bool
    plan_check: PlanCheckResult
    cost_check: CostDecision

    @model_validator(mode="after")
    def _check_consistency(self) -> "PlanReviewResult":
        expected_approved = self.plan_check.approved and self.cost_check.allowed
        if self.approved != expected_approved:
            raise ValueError(
                "approved phải khớp đúng: True chỉ khi CẢ plan_check.approved VÀ cost_check.allowed "
                "đều True — không được set approved khác với 2 điều kiện con."
            )
        return self
