import argparse
import sys

from cli.common import CliError, _open_context_store


def cmd_mark_stale(args: argparse.Namespace) -> int:
    """SPEC §4.6's staleness principle: khi 1 target/revision có thay đổi
    mà không xác định được chính xác phạm vi ảnh hưởng, đánh dấu CŨ RỘNG
    HƠN toàn bộ context đã lưu cho target đó (cả verified lẫn unverified)
    thay vì giữ lại dữ kiện có khả năng sai — "thà phân tích lại thừa còn
    hơn xây giả thuyết trên nền cũ". Đây là quyết định của con người/
    operator (biết target đã đổi revision), không phải thứ hệ thống tự
    phát hiện được — không có cách nào để code tự động biết "phạm vi ảnh
    hưởng không xác định được" nghĩa là gì cho 1 target cụ thể.
    """
    try:
        context_store = _open_context_store(args.context_db)
        try:
            marked = context_store.mark_stale(args.target_id, args.reason)
        except RuntimeError as exc:
            raise CliError(str(exc)) from exc
        finally:
            context_store.close()
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"-> Đã đánh dấu cũ {marked} bản ghi (verified + unverified) cho target_id '{args.target_id}'.")
    return 0
