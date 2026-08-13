import json
import sys
from pathlib import Path
from typing import List

from hypothesis_engine.llm_client.base import HypothesisLLMClient
from shared.id_generator import generate_id


class AgentBridgeLLMClient(HypothesisLLMClient):
    """Makes no API calls from this process itself. Writes the prompt to a
    file for an agent (e.g. the Claude Code session you're chatting with) to
    read and write a JSON reply into a response file, instead of making an
    HTTP call to a new provider.

    Important note: this is only a local dev/test convenience, NOT an
    architecture recognized by SPEC/A.html (§10.1 specifies "Kiro or an
    approved provider"), and it does NOT sidestep the AI-provider data-policy
    question (SPEC §9.7) — an agent replying through chat also runs on a
    third party's infrastructure (Anthropic), which is fundamentally no
    different from calling an API directly. Real target data still needs to
    go through the same ISMS/Gate 2 process as any other provider. The
    tradeoff is that each signal needs one manual step (asking the agent to
    process it, then pressing Enter), and the model version can't be pinned
    for reproducibility.
    """

    def __init__(self, work_dir: str = ".secweave_agent_bridge") -> None:
        self._work_dir = Path(work_dir)
        self._work_dir.mkdir(parents=True, exist_ok=True)
        # Separate run_id per client instantiation (each CLI run) — so 2
        # `hypothesize --llm-mode agent` processes running in the same
        # work_dir (e.g. one still hanging waiting for Enter) don't overwrite
        # each other's prompt/response files, even though each process's
        # counter starts from 1.
        self._run_id = generate_id("run")
        self._counter = 0

    def generate(self, prompt: str) -> str:
        self._counter += 1
        prompt_path = self._work_dir / f"prompt_{self._run_id}_{self._counter}.txt"
        response_path = self._work_dir / f"response_{self._run_id}_{self._counter}.txt"
        if response_path.exists():
            response_path.unlink()
        prompt_path.write_text(prompt, encoding="utf-8")

        self._wait_for_agent(prompt_path, response_path)

        if not response_path.exists():
            raise RuntimeError(f"Không tìm thấy file response tại '{response_path}'")
        return response_path.read_text(encoding="utf-8")

    def generate_many(self, prompts: List[str]) -> List[str]:
        """Merges multiple prompts into 1 file, waiting for the agent to
        reply exactly once — instead of repeating 'write prompt -> wait for
        Enter' for each signal individually. This way a report with N
        findings only needs 1 interaction round instead of N.
        """
        self._counter += 1
        prompt_path = self._work_dir / f"prompt_{self._run_id}_batch{self._counter}.txt"
        response_path = self._work_dir / f"response_{self._run_id}_batch{self._counter}.txt"
        if response_path.exists():
            response_path.unlink()

        sections = [
            f"Có {len(prompts)} signal cần lập giả thuyết bên dưới, đánh số 1..{len(prompts)}.",
            f"BẮT BUỘC: trả lời bằng ĐÚNG 1 JSON array gồm {len(prompts)} phần tử, đúng thứ tự "
            "1..N — mỗi phần tử là 1 object JSON (không phải string JSON lồng nhau) theo đúng "
            "format đã mô tả trong phần hướng dẫn riêng của từng signal bên dưới.",
        ]
        for i, prompt in enumerate(prompts, start=1):
            sections.append(f"===== SIGNAL {i}/{len(prompts)} =====\n{prompt}")
        prompt_path.write_text("\n\n".join(sections), encoding="utf-8")

        self._wait_for_agent(prompt_path, response_path)

        if not response_path.exists():
            raise RuntimeError(f"Không tìm thấy file response tại '{response_path}'")

        raw = response_path.read_text(encoding="utf-8")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"File response phải là JSON array hợp lệ: {exc}") from exc

        if not isinstance(parsed, list) or len(parsed) != len(prompts):
            actual = len(parsed) if isinstance(parsed, list) else type(parsed).__name__
            raise RuntimeError(
                f"File response phải là JSON array đúng {len(prompts)} phần tử theo thứ tự "
                f"1..{len(prompts)}, nhận được {actual}"
            )

        # Returns List[str] — each element re-encoded as a JSON string,
        # keeping the same return type as generate() so
        # HypothesisEngine.parse_response() can reuse its logic unchanged,
        # with no need to know anything about the batching.
        return [json.dumps(item, ensure_ascii=False) for item in parsed]

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
