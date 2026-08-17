import pytest
from pydantic import ValidationError

from shared.cost import check_planned_action_cap
from shared.models.action import ActionPlan, ActionSpec, ActionType


def _plan_with_n_actions(n: int) -> ActionPlan:
    action = ActionSpec(
        type=ActionType.READ_ONLY,
        method="GET",
        target="https://staging.example.com/api/objects/1",
        description="Read object 1.",
    )
    return ActionPlan(hypothesis_id="hyp_test1", actions=[action for _ in range(n)])


def test_plan_within_cap_is_allowed():
    decision = check_planned_action_cap(_plan_with_n_actions(3), cap=5)
    assert decision.allowed is True
    assert decision.planned_action_count == 3
    assert decision.cap == 5


def test_plan_exactly_at_cap_is_allowed():
    decision = check_planned_action_cap(_plan_with_n_actions(5), cap=5)
    assert decision.allowed is True


def test_plan_exceeding_cap_is_denied():
    decision = check_planned_action_cap(_plan_with_n_actions(6), cap=5)
    assert decision.allowed is False
    assert "vượt cap" in decision.reason
    assert decision.planned_action_count == 6
    assert decision.cap == 5


def test_empty_plan_cannot_be_constructed():
    # Real gap found via independent review: an empty ActionPlan used to be
    # constructible, making check_plan()'s all(...) over zero checks
    # vacuously True ("approved") and check_planned_action_cap's count=0
    # trivially within any cap — "approved, 0 actions" is never a
    # meaningful state to report as safe. ActionPlan.actions now requires
    # min_length=1, so this can't even be constructed in the first place —
    # same "an ambiguous/empty state must never look identical to a
    # verified-safe one" principle already applied to PlanCheckResult/
    # CostDecision's own consistency validators.
    with pytest.raises(ValidationError):
        _plan_with_n_actions(0)
