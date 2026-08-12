import sys
from pathlib import Path

from hypothesis_engine.llm_client.base import HypothesisLLMClient


class AgentBridgeLLMClient(HypothesisLLMClient):
    """Không gọi API nào từ chính process này. Ghi prompt ra file để agent (ví dụ
    Claude Code đang chat cùng bạn) đọc và tự viết câu trả lời JSON vào file
    response, thay vì gọi HTTP tới một provider mới.

    Lưu ý quan trọng: đây chỉ là tiện ích dev/test cục bộ, KHÔNG phải kiến trúc
    được SPEC/A.html công nhận (§10.1 chỉ định "Kiro hoặc provider đã được
    duyệt"), và KHÔNG né được câu hỏi chính sách gửi dữ liệu ra AI provider
    (SPEC §9.7) — agent trả lời qua chat cũng chạy trên hạ tầng của một bên
    thứ ba (Anthropic), về bản chất không khác gì gọi API trực tiếp. Dùng cho
    dữ liệu thật của target vẫn cần qua đúng quy trình ISMS/Gate 2 như mọi
    provider khác. Đổi lại là mỗi signal cần 1 bước thủ công (nhờ agent xử lý
    rồi Enter tiếp tục), và không pin được version model để tái hiện lại.
    """

    def __init__(self, work_dir: str = ".secweave_agent_bridge") -> None:
        self._work_dir = Path(work_dir)
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._counter = 0

    def generate(self, prompt: str) -> str:
        self._counter += 1
        prompt_path = self._work_dir / f"prompt_{self._counter}.txt"
        response_path = self._work_dir / f"response_{self._counter}.txt"
        if response_path.exists():
            response_path.unlink()
        prompt_path.write_text(prompt, encoding="utf-8")

        self._wait_for_agent(prompt_path, response_path)

        if not response_path.exists():
            raise RuntimeError(f"Không tìm thấy file response tại '{response_path}'")
        return response_path.read_text(encoding="utf-8")

    def _wait_for_agent(self, prompt_path: Path, response_path: Path) -> None:
        print(f"\n>>> Đã ghi prompt ra: {prompt_path}", file=sys.stderr)
        print(
            f">>> Nhờ agent đọc file trên, suy nghĩ theo đúng yêu cầu trong đó, "
            f"rồi ghi câu trả lời JSON (đúng schema đã yêu cầu trong prompt) vào: {response_path}",
            file=sys.stderr,
        )
        try:
            input(">>> Xong thì nhấn Enter để tiếp tục... ")
        except EOFError as exc:
            raise RuntimeError(
                "Chế độ --llm-mode agent cần terminal tương tác thật (chờ Enter) — "
                "không chạy được trong môi trường không có stdin (ví dụ script tự động, CI)."
            ) from exc
