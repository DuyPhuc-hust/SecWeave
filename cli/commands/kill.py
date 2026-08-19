import argparse
import sys

from cli.common import CliError, _parse_enum_arg
from shared.kill_switch import AutomaticThresholdReason, KillSwitch, StopSource


def cmd_kill(args: argparse.Namespace) -> int:
    """Dừng 1 execution từ CLI — gọi được từ process KHÁC với process đang
    thực sự chạy `execute` (vd operator hoảng, muốn dừng ngay giữa chừng
    từ terminal khác). Instance KillSwitch của lệnh này KHÔNG chạy cleanup
    thật (không có tham chiếu gì tới EvidenceHarness đang mở ở process
    kia) — process đang chạy `execute` tự đóng harness của NÓ khi
    capture() tiếp theo raise ExecutionStoppedError (sau khi tự
    KillSwitch.refresh() nhận ra dòng log mới do lệnh này ghi).
    """
    try:
        return _run_kill(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_kill(args: argparse.Namespace) -> int:
    # Real gap found via independent review: argparse's required=True only
    # checks the flag was passed, not that its value is non-empty (same
    # class of gap already closed for `execute --target-revision-id`).
    # `Path(storage_dir) / ""` evaluates to `storage_dir` itself — an empty
    # --execution-id silently pointed KillSwitch at the storage_dir ROOT
    # instead of erroring on the obviously-mistyped flag.
    if not args.execution_id:
        raise CliError("--execution-id không được để trống.")
    source = _parse_enum_arg(StopSource, args.source, "--source")

    automatic_threshold_reason = None
    if args.automatic_threshold_reason:
        automatic_threshold_reason = _parse_enum_arg(
            AutomaticThresholdReason, args.automatic_threshold_reason, "--automatic-threshold-reason"
        )

    kill_switch = KillSwitch(execution_id=args.execution_id, storage_dir=args.storage_dir)
    # Captured BEFORE stop() (which immediately appends its own event) —
    # real gap found via independent review: a mistyped/never-started
    # --execution-id silently succeeds (PREPARED is a valid, intentional
    # state to stop() from — "abort before start()" — so this can't just
    # be rejected outright), printing output textually IDENTICAL to a real
    # successful stop. An operator relying on this command for an
    # unambiguous panic-stop confirmation deserves an explicit signal that
    # nothing was actually running under this id.
    had_prior_history = bool(kill_switch.read_audit_log())

    try:
        event = kill_switch.stop(
            source=source,
            reason=args.reason,
            actor=args.actor,
            automatic_threshold_reason=automatic_threshold_reason,
        )
    except ValueError as exc:
        raise CliError(str(exc)) from exc

    print(f"-> execution '{args.execution_id}': {event.event.value}")
    print(f"   status hiện tại: {kill_switch.status.value}")
    if event.cleanup_status is not None:
        print(f"   cleanup (của riêng lệnh kill này, KHÔNG phải cleanup của process đang chạy): "
              f"{event.cleanup_status.value}")
    if not had_prior_history:
        print(
            f"   CẢNH BÁO: execution '{args.execution_id}' KHÔNG có lịch sử nào trước lệnh này "
            "(chưa từng start()) — kiểm tra lại --execution-id/--storage-dir có đúng không, có thể "
            "đây là gõ nhầm chứ không phải dừng đúng execution đang chạy.",
            file=sys.stderr,
        )

    return 0
