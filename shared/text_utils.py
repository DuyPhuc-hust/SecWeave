import re
from typing import Any

_FALSY_STRINGS = {"false", "0", "no", "null", "none", ""}

# Tìm fence ĐẦU TIÊN xuất hiện ở BẤT KỲ đâu trong text — một số model (ví dụ
# Llama qua Groq) không chỉ bọc JSON trong ```json ... ``` mà còn thêm cả đoạn
# văn giải thích trước/sau fence, dù prompt đã yêu cầu JSON thuần. Yêu cầu toàn
# bộ response phải BẮT ĐẦU bằng fence (như trước) bỏ sót đúng trường hợp này.
_FENCE_PATTERN = re.compile(r"```[^\n]*\n(.*?)\n```", re.DOTALL)


def is_truthy(value: Any) -> bool:
    """LLM đôi khi trả field bool ("verifiable"/"plannable") dưới dạng string
    ("false"/"true") hoặc số (0/1) thay vì bool JSON thuần — `value is False`
    chỉ bắt đúng bool, bỏ sót các dạng biểu diễn khác của "sai", khiến reason
    thật của LLM bị mất. Dùng chung cho mọi engine parse JSON output từ LLM.
    """
    if isinstance(value, str):
        return value.strip().lower() not in _FALSY_STRINGS
    return bool(value)


def strip_markdown_json_fence(text: str) -> str:
    """LLM thật hay bọc JSON trong ```json ... ``` dù prompt đã yêu cầu JSON thuần
    — có model còn thêm cả đoạn văn giải thích trước/sau fence chứ không chỉ bọc
    gọn JSON. Tìm fence đầu tiên xuất hiện ở bất kỳ đâu trong response; nếu không
    có fence nào thì trả nguyên text — không cố đoán/sửa JSON hỏng kiểu khác, để
    lỗi JSON thật sự vẫn được báo đúng thay vì bị che giấu.

    Dùng chung cho mọi engine parse JSON output từ LLM (Hypothesis Engine, Exploit
    Agent, ...) — không đặc thù cho riêng engine nào.
    """
    match = _FENCE_PATTERN.search(text)
    if match:
        return match.group(1).strip()
    return text.strip()
