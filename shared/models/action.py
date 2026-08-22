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


class SessionEstablishingLogin(BaseModel):
    """Declares that an ActionSpec's OWN response should establish a
    session for its identity — the generic, IN-PLAN form of what
    `--identity-logins` already does with STATIC, pre-plan-known
    credentials (cli/commands/execute.py's `_IdentityLoginSpec`).
    `--identity-logins` alone can't express a login whose target/
    parameters are only known at plan-authoring time as a real attack/
    login shape depending on an EARLIER action in the SAME plan (e.g. an
    SQLi payload targeting an identity/email a prior `{{FROM_STEP:...}}`
    step just registered) — its credentials are fixed JSON loaded BEFORE
    the plan's own actions, and FROM_STEP resolution, ever run.

    Extracted via `EvidenceHarness.login()` (not a bare `capture()`), so
    the resulting token attaches to this identity's client for every
    LATER action in the same execute run using the same identity — one
    generic mechanism, reusable for any target with a login/register
    pattern shaped this way, not specific to any one target's routes.

    `for_role` (an ObservationRole, NOT a free-form identity string) says
    WHICH role's identity this login establishes a session for — resolved
    through the SAME `role_identity.get(role, args.identity)` map every
    OTHER action already uses (cli/commands/execute.py). This is a
    deliberate design choice, not just a naming detail: this field is the
    one place `establishes_session` is reachable from Exploit Agent's own
    LLM-authored plans (see exploit_agent/agent.py's prompt), and the
    LLM is NEVER allowed to invent or see real identity labels/credentials
    — "Exploit Agent không hề chạm vào credential thật — plan chỉ mang
    role, LABEL/credential hoàn toàn do operator cấp qua CLI" (see
    cmd_execute's own docstring). Letting this field take an arbitrary
    string would have broken that boundary the moment the LLM could set
    it; `for_role` keeps the LLM working with the exact same 4-value
    vocabulary (main/positive_control/denied_control/setup) it already
    uses for the `role` field.

    An earlier version of this field WAS a free-form `identity: str` —
    reverted after realizing it couldn't be taught to the LLM without
    breaking the role-only boundary above. `for_role` also closes the
    original real gap that version was built for (identity used to be
    resolved purely by the ACTION'S OWN role, and `establishes_session`
    forces that to `setup`, so any OTHER unrelated role=setup action —
    e.g. a blind-marker bait-seed — would collide onto the same session
    by default): `for_role` deliberately targets a DIFFERENT role bucket
    than the login action's own (always `setup`, see the validator
    below), so it cannot collide with a sibling `role=setup` action's own
    default identity resolution — only with another action that
    genuinely, intentionally shares the same `for_role` bucket, which is
    the correct, INTENDED way a later action inherits this session.
    """

    for_role: ObservationRole
    token_json_path: str
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "

    @model_validator(mode="after")
    def _for_role_must_not_be_setup(self) -> "SessionEstablishingLogin":
        # for_role=setup would resolve through the EXACT SAME role bucket
        # this action's own (validator-enforced) role already occupies —
        # reintroducing the original collision this field exists to
        # avoid, the moment a plan has more than one role=setup action.
        # There is no legitimate scenario for it: "establish a session for
        # whichever identity plays the setup role" is inherently ambiguous
        # once 2+ setup actions exist, and meaningless with only 1 (that
        # would just be this action referring to itself).
        if self.for_role == ObservationRole.SETUP:
            raise ValueError(
                "SessionEstablishingLogin.for_role không được là 'setup' — action establishes_session "
                "LUÔN tự mang role=setup rồi (do EvidenceHarness.login() ép), for_role=setup sẽ khiến "
                "nó tự tham chiếu chính role của mình, va chạm với BẤT KỲ action role=setup nào khác "
                "trong cùng plan (đúng lỗi mà field này sinh ra để tránh)."
            )
        return self

    @model_validator(mode="after")
    def _token_json_path_must_be_non_empty(self) -> "SessionEstablishingLogin":
        # token_json_path is required, but pydantic's `str` accepts "" —
        # an empty value hits login()'s OWN `if not token_json_path:
        # return observation` early-return (the exact same shape as
        # _IdentityLoginSpec's legitimate "cookie-only, no token to
        # extract" case), silently making establishes_session a complete
        # no-op (capture succeeds, no error, no session header ever
        # attaches) despite the field being declared required. Reject
        # outright rather than let a typo look like a correctly-
        # configured session.
        if not self.token_json_path:
            raise ValueError(
                "SessionEstablishingLogin.token_json_path không được để trống — để trống khiến "
                "establishes_session âm thầm không làm gì cả (không lỗi, không session nào được "
                "thiết lập)."
            )
        return self


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
    # Assigned by Exploit Agent when it designs the plan — see cli/commands/execute.py's
    # `{{FROM_STEP:<step_id>:<json.path>}}` placeholder (resolved at
    # execution time, after step_id's action actually ran, never guessed
    # or invented by the LLM). None (the default) means this action's
    # response is never referenced by anything later — the overwhelming
    # majority of actions.
    step_id: Optional[str] = None

    # None (the default, the overwhelming majority of actions) means this
    # action is a plain capture() — no session established from it. When
    # set, EvidenceHarness.login() runs instead of capture() for this
    # action (see cli/commands/execute.py's per-action loop) — see
    # SessionEstablishingLogin's own docstring for why this exists
    # alongside --identity-logins rather than replacing it.
    establishes_session: Optional[SessionEstablishingLogin] = None

    @model_validator(mode="after")
    def _establishes_session_requires_setup_role(self) -> "ActionSpec":
        # EvidenceHarness.login() ALWAYS persists its observation with
        # role=SETUP, unconditionally — exactly the same real gap already
        # fixed once for --identity-logins's own pre-plan login actions
        # (see cli/commands/execute.py: "harness.login() ALWAYS internally
        # captures with role=SETUP regardless of what the ActionSpec
        # says"). An ActionSpec declaring role=main/positive_control/
        # denied_control alongside establishes_session would persist an
        # actions.json entry contradicting the observation `login()`
        # actually recorded — reject outright at construction time rather
        # than silently overriding the declared role (which could mask a
        # real authoring mistake) or letting the mismatch reach disk.
        if self.establishes_session is not None and self.role != ObservationRole.SETUP:
            raise ValueError(
                "establishes_session chỉ hợp lệ khi role=setup — EvidenceHarness.login() luôn ghi "
                "observation với role=SETUP bất kể ActionSpec khai gì; 1 action khai role khác (vd "
                "main/positive_control) kèm establishes_session sẽ khiến actions.json mâu thuẫn với "
                "observation thật. Nếu action này chỉ nhằm thiết lập session để MỘT action SAU đó "
                "(qua identity + {{FROM_STEP:...}} nếu cần) mới thực sự mang role dự kiến, đặt "
                "role=setup tường minh ở đây."
            )
        return self


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
