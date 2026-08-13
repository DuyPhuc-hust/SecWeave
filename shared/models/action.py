from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator


class ActionType(str, Enum):
    """SPEC §4.2 — chỉ 2 loại hành động được xem xét cho phép trong pilot.

    Hành động xóa/sửa dữ liệu hiện hữu, đổi cấu hình, ảnh hưởng khả dụng, hay
    quét diện rộng KHÔNG có giá trị enum tương ứng — không thể construct được
    một ActionType thuộc các loại đó, dù chỉ để thử nghiệm.
    """

    READ_ONLY = "read_only"
    TEST_DATA_CREATION = "test_data_creation"


class ActionSpec(BaseModel):
    """Một hành động dự kiến trong ActionPlan. Tên field khớp weekly plan W5:
    `is_allowed(action: ActionSpec) -> PolicyDecision`.

    Model này CHỈ giữ dữ liệu — không tự chặn method nguy hiểm (ví dụ DELETE).
    Việc chặn thuộc về Policy Service (shared/policy.py), để adversarial test
    có thể construct đúng loại ActionSpec vi phạm rồi xác nhận bị is_allowed()
    từ chối, thay vì bị Pydantic chặn trước khi tới được Policy Service.
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
    """Kết quả build_plan — mirror HypothesisResult: engine có thể trả về kế
    hoạch thật, hoặc từ chối kèm lý do (khi Hypothesis không đủ cụ thể để lập
    kế hoạch hành động) — không có trạng thái lấp lửng ở giữa.
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
    """Kết quả đối chiếu toàn bộ ActionPlan với allowlist — deny-by-default:
    approved chỉ True khi TẤT CẢ action đều pass, không tự lược bỏ action fail
    rồi coi phần còn lại là approved (đúng nguyên tắc weekly plan W5).
    """

    approved: bool
    checks: List[ActionCheckResult]


class CostDecision(BaseModel):
    """Kết quả Cost Service (khung) — weekly plan W5: chỉ đếm số hành động DỰ
    KIẾN trong plan so với cap, chưa đếm hành động thật (cần Evidence Harness
    thật thực thi, tuần sau mới có)."""

    allowed: bool
    reason: str
    planned_action_count: int
    cap: int


class PlanReviewResult(BaseModel):
    """Cổng duy nhất trước khi 1 ActionPlan được coi là an toàn để đi tiếp —
    gộp cả allowlist check (PlanCheckResult) lẫn cost-cap check (CostDecision)
    thành 1 boolean, để không ai vô tình chỉ gọi 1 trong 2 rồi coi plan là đã
    được duyệt đầy đủ.
    """

    approved: bool
    plan_check: PlanCheckResult
    cost_check: CostDecision
