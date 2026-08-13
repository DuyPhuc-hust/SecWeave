from shared.models.action import ActionPlan, CostDecision


def check_planned_action_cap(plan: ActionPlan, cap: int) -> CostDecision:
    """Cost Service (khung) — weekly plan W5: "đếm số hành động dự kiến trong
    plan, so với cap (giờ mới đếm dự kiến, tuần sau mới đếm hành động thật)".

    Đếm hành động THẬT đã thực thi (không chỉ dự kiến) là việc của tuần có
    Evidence Harness — hàm này không thay thế control cost-cap lúc runtime.
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
