import argparse
import sys

from cli.common import CliError
from shared.kill_switch import KillSwitch


def cmd_resume(args: argparse.Namespace) -> int:
    """Cho phép 1 execution đã STOPPED quay lại RUNNING — đường DUY NHẤT
    (SPEC §6.4 control #10) — để hoàn thiện vòng execute -> kill -> resume
    -> execute lại mà `cmd_execute` giờ yêu cầu tường minh khi gặp STOPPED.
    """
    try:
        return _run_resume(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_resume(args: argparse.Namespace) -> int:
    # See `_run_kill`'s identical check for why an empty string must be rejected.
    if not args.execution_id:
        raise CliError("--execution-id không được để trống.")
    kill_switch = KillSwitch(execution_id=args.execution_id, storage_dir=args.storage_dir)
    try:
        kill_switch.resume(actor=args.actor, authorization_reference=args.authorization_reference)
    except ValueError as exc:
        raise CliError(str(exc)) from exc
    except RuntimeError as exc:
        # resume()'s own audit-log write can fail (disk full, permission
        # loss) AFTER this instance's in-memory status already flipped to
        # RUNNING — same reasoning as _run_kill's identical RuntimeError
        # handling: must not crash uncaught for this safety-critical path.
        raise CliError(str(exc)) from exc

    print(f"-> execution '{args.execution_id}': resume")
    print(f"   status hiện tại: {kill_switch.status.value}")
    return 0
