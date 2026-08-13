import json
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from hypothesis_engine.llm_client.base import HypothesisLLMClient
from shared.id_generator import generate_id
from shared.models.hypothesis import (
    Hypothesis,
    HypothesisProvenance,
    HypothesisResult,
    HypothesisStatus,
)
from shared.models.signal import NormalizedSignal

REQUIRED_FIELDS = ("expected_behavior", "suspected_behavior", "observation_criteria")

_FALSY_STRINGS = {"false", "0", "no", "null", "none", ""}


def _is_truthy(value: Any) -> bool:
    # LLM đôi khi trả "verifiable" dưới dạng string ("false"/"true") hoặc số
    # (0/1) thay vì bool JSON thuần — `value is False` chỉ bắt đúng bool, bỏ
    # sót các dạng biểu diễn khác của "sai", khiến reason thật của LLM bị mất.
    if isinstance(value, str):
        return value.strip().lower() not in _FALSY_STRINGS
    return bool(value)


def _strip_markdown_json_fence(text: str) -> str:
    """LLM thật hay bọc JSON trong ```json ... ``` dù prompt đã yêu cầu JSON thuần.
    Chỉ xử lý đúng dạng fence phổ biến này — không cố đoán/sửa JSON hỏng kiểu khác,
    để lỗi JSON thật sự vẫn được báo đúng là NOT_VERIFIABLE thay vì bị che giấu.
    """
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped

    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines)


class HypothesisEngine:
    def __init__(self, llm_client: HypothesisLLMClient) -> None:
        self._llm_client = llm_client

    def generate_hypothesis(
        self,
        signal: NormalizedSignal,
        source_snippet: Optional[str] = None,
        verified_context: Optional[List[Dict[str, Any]]] = None,
    ) -> HypothesisResult:
        prompt = self.build_prompt(signal, source_snippet, verified_context)
        raw_output = self._llm_client.generate(prompt)
        return self.parse_response(raw_output, signal)

    def build_prompt(
        self,
        signal: NormalizedSignal,
        source_snippet: Optional[str],
        verified_context: Optional[List[Dict[str, Any]]],
    ) -> str:
        parts = [
            "Bạn nhận một NormalizedSignal đã chuẩn hoá từ một scanner bảo mật.",
            "Nhiệm vụ: đề xuất MỘT giả thuyết kiểm chứng được, KHÔNG kết luận có/không có lỗ hổng.",
            "Trả về đúng JSON với các trường: verifiable (bool), và nếu verifiable=true thì kèm "
            "expected_behavior, suspected_behavior, observation_criteria (đều là string). "
            "Nếu verifiable=false, kèm reason (string) giải thích vì sao không đủ để lập giả thuyết.",
            "BẮT BUỘC: viết toàn bộ nội dung text (expected_behavior, suspected_behavior, "
            "observation_criteria, reason) bằng tiếng Anh — chỉ phần hướng dẫn này là tiếng Việt.",
            "Lưu ý khi viết observation_criteria: signal chỉ cho biết NƠI phát hiện, không đảm bảo "
            "hành vi/luồng dữ liệu liên quan thực sự tồn tại hay đích thực thi thực sự trùng với nơi "
            "phát hiện. Nếu observation_criteria cần một điều kiện tiên quyết như vậy mới có ý nghĩa "
            "(ví dụ: phải xác nhận trước một hành vi có được dùng không, hoặc phải xác định đúng đích "
            "thực thi thay vì suy luận từ vị trí phát hiện), hãy nêu rõ điều kiện đó như bước đầu tiên "
            "trong observation_criteria.",
            f"Signal: {signal.model_dump_json()}",
        ]
        if source_snippet:
            parts.append(f"Source code liên quan:\n{source_snippet}")
        if verified_context:
            parts.append(f"Ngữ cảnh đã verified từ lần chạy trước: {json.dumps(verified_context, ensure_ascii=False)}")
        return "\n\n".join(parts)

    def parse_response(self, raw_output: str, signal: NormalizedSignal) -> HypothesisResult:
        try:
            data = json.loads(_strip_markdown_json_fence(raw_output))
        except json.JSONDecodeError:
            return HypothesisResult(
                status=HypothesisStatus.NOT_VERIFIABLE,
                reason="LLM trả về output không phải JSON hợp lệ",
            )

        if not isinstance(data, dict):
            return HypothesisResult(
                status=HypothesisStatus.NOT_VERIFIABLE,
                reason="LLM trả về JSON không đúng cấu trúc object",
            )

        if "verifiable" not in data:
            # Thiếu hẳn field bắt buộc "verifiable" — khác với "verifiable=true"
            # thật sự. Không được coi đây là hợp lệ chỉ vì 3 field text kia
            # tình cờ có mặt: LLM chưa từng khẳng định tín hiệu kiểm chứng được.
            return HypothesisResult(
                status=HypothesisStatus.NOT_VERIFIABLE,
                reason="LLM output thiếu field bắt buộc: verifiable",
            )

        if not _is_truthy(data["verifiable"]):
            reason = data.get("reason") or "LLM đánh giá tín hiệu không đủ để lập giả thuyết"
            return HypothesisResult(status=HypothesisStatus.NOT_VERIFIABLE, reason=reason)

        missing = [field for field in REQUIRED_FIELDS if not data.get(field)]
        if missing:
            return HypothesisResult(
                status=HypothesisStatus.NOT_VERIFIABLE,
                reason=f"LLM output thiếu field bắt buộc: {', '.join(missing)}",
            )

        try:
            hypothesis = Hypothesis(
                hypothesis_id=generate_id("hyp"),
                expected_behavior=data["expected_behavior"],
                suspected_behavior=data["suspected_behavior"],
                observation_criteria=data["observation_criteria"],
                provenance=HypothesisProvenance(
                    source_tool=signal.source.tool,
                    source_signal_id=signal.signal_id,
                    coverage=signal.source.coverage,
                ),
            )
        except ValidationError as exc:
            return HypothesisResult(
                status=HypothesisStatus.NOT_VERIFIABLE,
                reason=f"LLM output không khớp schema Hypothesis: {exc}",
            )

        return HypothesisResult(status=HypothesisStatus.HYPOTHESIS, hypothesis=hypothesis)
