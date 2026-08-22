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
    # An empty string is not the same as the flag being omitted —
    # Path(storage_dir) / "" evaluates to storage_dir itself, silently
    # pointing KillSwitch at the storage_dir root instead of erroring.
    if not args.execution_id:
        raise CliError("--execution-id không được để trống.")
    source = _parse_enum_arg(StopSource, args.source, "--source")

    automatic_threshold_reason = None
    if args.automatic_threshold_reason:
        automatic_threshold_reason = _parse_enum_arg(
            AutomaticThresholdReason, args.automatic_threshold_reason, "--automatic-threshold-reason"
        )

    kill_switch = KillSwitch(execution_id=args.execution_id, storage_dir=args.storage_dir)
    # Captured before stop() appends its own event — PREPARED is a valid
    # state to stop() from (abort before start()), so a mistyped/never-
    # started --execution-id would otherwise print output identical to a
    # real successful stop, with no signal that nothing was running.
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
    except RuntimeError as exc:
        # stop()'s own audit-log write can fail (disk full, permission
        # loss) AFTER this instance's in-memory status already flipped to
        # STOPPED — for an emergency-stop command specifically, silently
        # crashing here would be worse than a normal command failing: the
        # operator would have no way to tell "the stop never took effect"
        # from "the stop worked but couldn't be durably recorded, so a
        # separate running `execute` process won't see it via refresh()".
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
