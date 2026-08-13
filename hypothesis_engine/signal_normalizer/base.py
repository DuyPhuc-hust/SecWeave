from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

from shared.models.signal import NormalizedSignal, RawReference, SignalCoverage

OnSkipCallback = Callable[[str], None]


class SignalAdapter(ABC):
    tool_name: str

    @abstractmethod
    def parse(
        self,
        raw_report: Dict[str, Any],
        raw_reference: RawReference,
        tool_version: str,
        coverage: SignalCoverage,
        on_skip: Optional[OnSkipCallback] = None,
    ) -> List[NormalizedSignal]:
        """Chuyển raw_report thành danh sách NormalizedSignal.

        Một entry lỗi (thiếu field bắt buộc, sai kiểu) không được làm mất các
        entry hợp lệ khác trong cùng report — adapter phải bỏ qua đúng entry
        đó, gọi on_skip(mô tả lý do) nếu có, và tiếp tục xử lý phần còn lại.
        """
        ...
