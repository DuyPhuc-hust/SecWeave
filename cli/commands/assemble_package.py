import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from cli.common import CliError, _parse_enum_arg
from shared.models.action import ActionSpec
from shared.models.entities import Authorization, AuthorizationLayer
from shared.models.kill_switch import ExecutionStatus
from shared.models.observation import NormalizedObservation
from shared.models.verification_package import Environment
from verification_package.assembler import assemble_verification_package


def cmd_assemble_package(args: argparse.Namespace) -> int:
    """Lắp `VerificationPackage` (SPEC §7) từ artifact thật của 1 lượt
    `execute` đã chạy — tách riêng khỏi `execute` có chủ đích (real gap
    tìm được qua review: trước lệnh này, `assemble_verification_package()`
    đã build/test đầy đủ nhưng chỉ gọi được qua Python API, không có CLI
    nào cả). Đọc lại 3 artifact `execute` đã lưu (`observations.jsonl`,
    `actions.json`, `execution_status.json`) trong cùng thư mục
    execution — không cần `--plan-file` gốc vẫn còn tồn tại.

    4 field bắt buộc (`--scenario`, `--limitations`, `--next-action`,
    `--authorization-reference`) là phán đoán của con người, không tự sinh
    được — cố tình KHÔNG có giá trị mặc định nào, khớp lý do
    `assemble_verification_package()` giữ các field này tách khỏi
    execution hot path.
    """
    try:
        return _run_assemble_package(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_assemble_package(args: argparse.Namespace) -> int:
    # Real gap found via independent review: same "empty string is not the
    # same as flag omitted" gap already fixed for `kill`/`resume`/`execute`
    # — `Path(storage_dir) / ""` resolves to storage_dir itself, so an
    # empty --execution-id would silently read whatever loose
    # observations.jsonl/actions.json/execution_status.json happen to sit
    # directly under --storage-dir instead of erroring on the mistyped flag.
    if not args.execution_id:
        raise CliError("--execution-id không được để trống.")
    execution_dir = Path(args.storage_dir) / args.execution_id

    observations_path = execution_dir / "observations.jsonl"
    actions_path = execution_dir / "actions.json"
    status_path = execution_dir / "execution_status.json"
    for path, hint in (
        (observations_path, "chưa có observation nào — execution này đã thực sự chạy `execute` chưa?"),
        (actions_path, "thiếu file action — chỉ `execute` mới tự sinh file này."),
        (status_path, "thiếu execution_status — chỉ `execute` mới tự sinh file này."),
    ):
        if not path.exists():
            raise CliError(f"không tìm thấy '{path}' — {hint}")

    try:
        observation_dicts = [
            json.loads(line) for line in observations_path.read_text(encoding="utf-8").splitlines() if line
        ]
        actions_data = json.loads(actions_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise CliError(f"không đọc được artifact của execution '{args.execution_id}': {exc}") from exc
    # Real gap found via independent review: this parsing used to go
    # straight from json.loads() into Model(**item) with no shape check —
    # `measure`'s own read of the exact same 2 artifact kinds was hardened
    # this way, but assemble-package (which reads them first, and is the
    # one call site that always must have run before `measure` or `report`
    # can do anything useful) never got the same guard, so a hand-edited or
    # torn observations.jsonl/actions.json (both operator-editable files by
    # design — see `review-package`'s own docstring on this exact risk)
    # could crash with a raw TypeError instead of a clean CliError.
    if not all(isinstance(o, dict) for o in observation_dicts):
        raise CliError(f"'{observations_path}' có dòng không phải JSON object — file này có bị sửa tay không?")
    if not isinstance(actions_data, list) or not all(isinstance(item, dict) for item in actions_data):
        raise CliError(f"'{actions_path}' phải là 1 danh sách ActionSpec (JSON object) — file này có bị sửa tay không?")
    try:
        observations = [NormalizedObservation(**o) for o in observation_dicts]
        actions = [ActionSpec(**item) for item in actions_data]
        execution_status = ExecutionStatus(json.loads(status_path.read_text(encoding="utf-8"))["execution_status"])
    except (json.JSONDecodeError, ValidationError, ValueError, OSError) as exc:
        raise CliError(f"không đọc được artifact của execution '{args.execution_id}': {exc}") from exc

    environment = _parse_enum_arg(Environment, args.environment, "--environment")

    print(
        "CẢNH BÁO: authorization dùng để lắp package dưới đây CHỈ dựng tạm từ --authorization-reference "
        "cho test cục bộ — KHÔNG phải hồ sơ Gate 2/3 thật đã duyệt.",
        file=sys.stderr,
    )
    authorization = Authorization(
        id=args.authorization_reference,
        layer=AuthorizationLayer.TARGET_AUTHORIZATION,
        approved_by="cli-local-test",
        approved_at=datetime.now(timezone.utc),
        target_id=args.target_id,
        target_revision_id=args.target_revision_id,
    )

    try:
        package = assemble_verification_package(
            target_id=args.target_id,
            environment=environment,
            revision=args.target_revision_id,
            authorization=authorization,
            scenario=args.scenario,
            execution_id=args.execution_id,
            actions=actions,
            observations=observations,
            execution_status=execution_status,
            limitations=args.limitations,
            next_action=args.next_action,
        )
    except (ValueError, ValidationError) as exc:
        raise CliError(f"không lắp được Verification Package: {exc}") from exc

    if args.format == "json":
        print(package.model_dump_json(indent=2))
    else:
        print(f"package_id: {package.package_id}")
        print(f"verdict: {package.verdict.value} — {package.verdict_reason}")
        print(f"identities: {', '.join(package.identities)}")
        print(f"action_record: {len(package.action_record)} action(s)")
        missing = package.missing_fields_for_release()
        print(f"is_release_ready: {package.is_release_ready}" + (f" (thiếu: {missing})" if missing else ""))
    return 0
