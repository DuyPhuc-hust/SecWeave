import pytest
from pydantic import ValidationError

from shared.models.action import (
    ActionCheckResult,
    ActionPlan,
    ActionPlanResult,
    ActionPlanStatus,
    ActionSpec,
    ActionType,
    CostDecision,
    PlanCheckResult,
    PlanReviewResult,
    PolicyDecision,
)


def _action() -> ActionSpec:
    return ActionSpec(type=ActionType.READ_ONLY, method="GET", target="https://x.example.com/a", description="d")


def _check(allowed: bool) -> ActionCheckResult:
    return ActionCheckResult(action=_action(), decision=PolicyDecision(allowed=allowed, reason="r"))


# ----- ActionPlanResult: real gap found via independent review — the
# consistency validator only checked PLANNED-requires-plan and
# NOT_PLANNABLE-requires-reason, never the reverse: NOT_PLANNABLE must NOT
# carry a plan. A future caller reading `.plan` without checking `.status`
# first could silently act on a plan the engine explicitly refused. -----


def test_action_plan_result_accepts_planned_with_a_plan():
    plan = ActionPlan(hypothesis_id="hyp_1", actions=[_action()])
    result = ActionPlanResult(status=ActionPlanStatus.PLANNED, plan=plan)
    assert result.status == ActionPlanStatus.PLANNED


def test_action_plan_result_accepts_not_plannable_with_a_reason():
    result = ActionPlanResult(status=ActionPlanStatus.NOT_PLANNABLE, reason="no endpoint")
    assert result.plan is None


def test_action_plan_result_rejects_planned_without_a_plan():
    with pytest.raises(ValidationError):
        ActionPlanResult(status=ActionPlanStatus.PLANNED, plan=None)


def test_action_plan_result_rejects_not_plannable_without_a_reason():
    with pytest.raises(ValidationError):
        ActionPlanResult(status=ActionPlanStatus.NOT_PLANNABLE, reason=None)


def test_action_plan_result_rejects_not_plannable_carrying_a_plan():
    plan = ActionPlan(hypothesis_id="hyp_1", actions=[_action()])
    with pytest.raises(ValidationError):
        ActionPlanResult(status=ActionPlanStatus.NOT_PLANNABLE, reason="no endpoint", plan=plan)


# ----- PlanCheckResult: real gap found via independent review — approved
# used to be settable independently of checks[], unlike ActionPlanResult/
# HypothesisResult which already enforce this kind of consistency. -----


def test_plan_check_result_accepts_approved_true_when_all_checks_allowed():
    result = PlanCheckResult(approved=True, checks=[_check(True), _check(True)])
    assert result.approved is True


def test_plan_check_result_accepts_approved_false_when_any_check_denied():
    result = PlanCheckResult(approved=False, checks=[_check(True), _check(False)])
    assert result.approved is False


def test_plan_check_result_rejects_approved_true_when_a_check_is_denied():
    with pytest.raises(ValidationError):
        PlanCheckResult(approved=True, checks=[_check(True), _check(False)])


def test_plan_check_result_rejects_approved_false_when_all_checks_allowed():
    with pytest.raises(ValidationError):
        PlanCheckResult(approved=False, checks=[_check(True), _check(True)])


# ----- CostDecision: allowed must match planned_action_count <= cap -----


def test_cost_decision_accepts_allowed_true_within_cap():
    decision = CostDecision(allowed=True, reason="ok", planned_action_count=3, cap=10)
    assert decision.allowed is True


def test_cost_decision_rejects_allowed_true_over_cap():
    with pytest.raises(ValidationError):
        CostDecision(allowed=True, reason="ok", planned_action_count=11, cap=10)


def test_cost_decision_rejects_allowed_false_within_cap():
    with pytest.raises(ValidationError):
        CostDecision(allowed=False, reason="ok", planned_action_count=3, cap=10)


# ----- PlanReviewResult: approved must match plan_check.approved AND
# cost_check.allowed together -----


def test_plan_review_result_accepts_approved_true_when_both_pass():
    plan_check = PlanCheckResult(approved=True, checks=[_check(True)])
    cost_check = CostDecision(allowed=True, reason="ok", planned_action_count=1, cap=10)
    result = PlanReviewResult(approved=True, plan_check=plan_check, cost_check=cost_check)
    assert result.approved is True


def test_plan_review_result_rejects_approved_true_when_cost_check_fails():
    plan_check = PlanCheckResult(approved=True, checks=[_check(True)])
    cost_check = CostDecision(allowed=False, reason="over cap", planned_action_count=11, cap=10)
    with pytest.raises(ValidationError):
        PlanReviewResult(approved=True, plan_check=plan_check, cost_check=cost_check)


def test_plan_review_result_rejects_approved_true_when_plan_check_fails():
    plan_check = PlanCheckResult(approved=False, checks=[_check(False)])
    cost_check = CostDecision(allowed=True, reason="ok", planned_action_count=1, cap=10)
    with pytest.raises(ValidationError):
        PlanReviewResult(approved=True, plan_check=plan_check, cost_check=cost_check)
