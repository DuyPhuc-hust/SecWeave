from shared.models.action import ActionPlan, CostDecision


def check_planned_action_cap(plan: ActionPlan, cap: int) -> CostDecision:
    """Cost Service (skeleton) — weekly plan W5: "count the planned actions in
    the plan against a cap (only planned actions for now, actual executed
    actions come the following week)".

    Counting REAL executed actions (not just planned ones) is the job of the
    week that adds Evidence Harness — this function does not replace the
    runtime cost-cap control.
    """
    count = len(plan.actions)
    if count > cap:
        return CostDecision(
            allowed=False,
            reason=f"Kế hoạch có {count} hành động dự kiến, vượt cap cho phép ({cap}).",
            planned_action_count=count,
            cap=cap,
        )
    return CostDecision(
        allowed=True,
        reason=f"Kế hoạch có {count} hành động dự kiến, trong cap cho phép ({cap}).",
        planned_action_count=count,
        cap=cap,
    )
