import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from pydantic import ValidationError

from cli.common import CliError, _build_local_test_authorization, _read_verdict_for_execution
from shared.models.action import ActionSpec
from shared.models.verification_package import VerificationPackage
from shared.policy import is_allowed


def cmd_measure(args: argparse.Namespace) -> int:
    """SPEC §8.1 — gộp báo cáo các chỉ số đo được vào 1 lệnh, thay vì phải tự
    chạy/tự đọc từng file rời rạc (VerificationPackage, retest summary,
    audit log) rồi tự cộng bằng tay. Bảng SPEC §8.1 có 5 dòng dù header ghi
    "bốn nhóm chỉ số" — dòng thứ 5 ("khả năng bàn giao") được giữ lại ở đây
    thay vì bỏ sót, dù không tự động hoá được. KHÔNG tính điểm/quyết định
    release thay ai cả (đó là việc của `review-package`) — chỉ tổng hợp lại
    số liệu THẬT đã có sẵn từ các lệnh khác; mỗi input đều tuỳ chọn, đo được
    gì thì đo, không có gì thì báo N/A chứ không giả định:

      1. Schema completeness (nhị phân) — `--package-file`, tái dùng
         VerificationPackage.missing_fields_for_release()/is_release_ready
         đã có sẵn, không tính lại logic ở đây.
      2. ECS (Evidence Completeness Score) — SPEC ghi rõ "Proposed/TBD",
         chưa có rubric/threshold nào để tính — luôn báo N/A bất kể input.
      3. Reproducibility — `--retest-summary`, đọc lại file `secweave
         retest` đã sinh; nếu `--storage-dir` trỏ đúng execution dir của
         từng lần retest, đối chiếu lại (best-effort, CHỈ CẢNH BÁO không
         chặn cứng — lệnh này là báo cáo chứ không phải gate release như
         `review-package`) verdict khai trong summary với verdict tính lại
         từ raw artifact thật.
      4. Control effectiveness — `--execution-id` (+ `--allowed-action`
         lặp lại nếu muốn đối chiếu allowlist bằng đúng `is_allowed()` mà
         Policy Service thật dùng, không viết lại logic khớp allowlist ở
         đây), đọc lại actions.json/kill_switch_audit_log.jsonl/
         cost_audit_log.jsonl thật của 1 execution đã chạy.
      5. Khả năng bàn giao — cần runbook/con người test thật, không tự
         động hoá được bằng CLI — luôn báo N/A.
    """
    try:
        return _run_measure(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_measure(args: argparse.Namespace) -> int:
    if not args.package_file and not args.retest_summary and not args.execution_id:
        raise CliError(
            "measure cần ít nhất 1 trong --package-file/--retest-summary/--execution-id — không có gì để đo."
        )
    if args.allowed_action and not args.execution_id:
        print(
            "CẢNH BÁO: --allowed-action không có tác dụng gì nếu không có --execution-id đi kèm (chỉ dùng "
            "để đối chiếu actions.json của 1 execution cụ thể) — bỏ qua.",
            file=sys.stderr,
        )

    report: Dict[str, Any] = {}

    if args.package_file:
        package_path = Path(args.package_file)
        try:
            package_data = json.loads(package_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise CliError(f"không tìm thấy package file '{package_path}'")
        except OSError as exc:
            raise CliError(f"không đọc được package file '{package_path}': {exc}") from exc
        except json.JSONDecodeError as exc:
            raise CliError(f"'{package_path}' không phải JSON hợp lệ: {exc}") from exc
        if not isinstance(package_data, dict):
            raise CliError(f"'{package_path}' phải là 1 JSON object (VerificationPackage), nhận '{type(package_data).__name__}'.")
        try:
            package = VerificationPackage(**package_data)
        except ValidationError as exc:
            raise CliError(f"'{package_path}' không phải VerificationPackage hợp lệ: {exc}") from exc
        missing = package.missing_fields_for_release()
        report["schema_completeness"] = {"is_release_ready": package.is_release_ready, "missing_fields": missing}
    else:
        report["schema_completeness"] = {"status": "N/A — không truyền --package-file"}

    report["ecs"] = {
        "status": "N/A — SPEC §8.1 ghi rõ ECS là 'Proposed/TBD', chưa có rubric/threshold để tính",
    }

    if args.retest_summary:
        summary_path = Path(args.retest_summary)
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise CliError(f"không tìm thấy retest summary '{summary_path}'")
        except OSError as exc:
            raise CliError(f"không đọc được retest summary '{summary_path}': {exc}") from exc
        except json.JSONDecodeError as exc:
            raise CliError(f"'{summary_path}' không phải JSON hợp lệ: {exc}") from exc
        if not isinstance(summary, dict):
            raise CliError(f"'{summary_path}' phải là 1 JSON object (retest summary), nhận '{type(summary).__name__}'.")
        required_summary_fields = ("runs", "agreement_ratio", "meets_recommended_threshold", "results")
        missing_summary_fields = [f for f in required_summary_fields if f not in summary]
        if missing_summary_fields:
            raise CliError(
                f"'{summary_path}' thiếu field {missing_summary_fields} — không giống file do `secweave "
                "retest` sinh ra."
            )
        if not isinstance(summary.get("agreement_ratio"), (int, float)) or isinstance(summary.get("agreement_ratio"), bool):
            raise CliError(f"'{summary_path}': agreement_ratio phải là số, nhận '{summary.get('agreement_ratio')}'.")
        if not isinstance(summary.get("results"), list) or not all(isinstance(e, dict) for e in summary["results"]):
            raise CliError(f"'{summary_path}': results phải là 1 danh sách object {{execution_id, verdict}}.")

        mismatches = []
        cross_checked = 0
        corrupted_artifact_count = 0
        for entry in summary["results"]:
            execution_id = entry.get("execution_id")
            declared_verdict = entry.get("verdict")
            execution_dir = Path(args.storage_dir) / str(execution_id)
            if not (execution_dir / "observations.jsonl").exists() or not (execution_dir / "execution_status.json").exists():
                continue
            try:
                recomputed_verdict = _read_verdict_for_execution(execution_id, args.storage_dir)
            except CliError:
                # Real gap found via independent review: `cross_checked`
                # used to be incremented BEFORE this try/except, so a
                # corrupted/torn artifact (the files exist, but
                # _read_verdict_for_execution can't parse them) still
                # counted toward "N cross-checked" even though the
                # comparison against the declared verdict never actually
                # happened — silently defeating the exact tamper-detection
                # purpose this cross-check exists for (a hand-edited
                # summary next to a genuinely corrupted artifact would
                # report "N/N cross-checked, no mismatch" while having
                # verified nothing for that run).
                corrupted_artifact_count += 1
                continue
            cross_checked += 1
            if recomputed_verdict != declared_verdict:
                mismatches.append(
                    {
                        "execution_id": execution_id,
                        "khai_trong_summary": declared_verdict,
                        "tinh_lai_tu_raw_artifact": recomputed_verdict,
                    }
                )

        report["reproducibility"] = {
            "retest_id": summary.get("retest_id"),
            "runs": summary.get("runs"),
            "most_common_verdict": summary.get("most_common_verdict"),
            "agreement_ratio": summary.get("agreement_ratio"),
            "meets_recommended_threshold": summary.get("meets_recommended_threshold"),
            "runs_with_no_verdict": summary.get("runs_with_no_verdict"),
            "cross_checked_against_raw_artifact": cross_checked,
            "runs_with_corrupted_artifact": corrupted_artifact_count,
        }
        if corrupted_artifact_count:
            print(
                f"CẢNH BÁO: {corrupted_artifact_count} lần retest có artifact tồn tại nhưng KHÔNG đọc lại "
                "được để đối chiếu (observations.jsonl/execution_status.json bị hỏng) — những lần này "
                "KHÔNG được tính vào cross_checked_against_raw_artifact, và verdict khai trong summary "
                "của chúng chưa được kiểm chứng lại.",
                file=sys.stderr,
            )
        if mismatches:
            report["reproducibility"]["WARNING_mismatch_with_raw_artifact"] = mismatches
            print(
                f"CẢNH BÁO: {len(mismatches)} lần retest có verdict khai trong summary KHÁC với verdict "
                "tính lại từ raw artifact thật (observations.jsonl + execution_status.json trong "
                "--storage-dir) — summary này có thể đã bị sửa tay, kiểm tra lại trước khi dùng số liệu "
                "reproducibility ở trên.",
                file=sys.stderr,
            )
        elif summary["results"] and cross_checked == 0:
            # If NOTHING cross-checked (e.g. wrong --storage-dir), the JSON
            # output would otherwise look identical to "checked N/N, all
            # matched" — must say so explicitly, same principle as
            # actions_outside_allowlist_count reporting "N/A" instead of 0
            # when --allowed-action was never given.
            report["reproducibility"]["WARNING_could_not_cross_check_any_run"] = (
                f"Không đối chiếu được lần retest nào với raw artifact thật (0/{len(summary['results'])}) — "
                "kiểm tra lại --storage-dir có đúng thư mục đã dùng khi `secweave retest` chạy không. Số "
                "liệu reproducibility ở trên HOÀN TOÀN dựa vào nội dung tự khai của file summary, chưa "
                "được kiểm chứng lại."
            )
            print(
                f"CẢNH BÁO: không đối chiếu được lần retest nào (0/{len(summary['results'])}) với raw "
                "artifact thật dưới --storage-dir đã truyền — số liệu reproducibility ở trên chưa được "
                "kiểm chứng, chỉ là nội dung tự khai của file summary.",
                file=sys.stderr,
            )
    else:
        report["reproducibility"] = {"status": "N/A — không truyền --retest-summary"}

    if args.execution_id:
        execution_dir = Path(args.storage_dir) / args.execution_id
        actions_path = execution_dir / "actions.json"
        if not actions_path.exists():
            raise CliError(
                f"không tìm thấy '{actions_path}' — execution '{args.execution_id}' đã thực sự `execute` chưa?"
            )
        try:
            actions_data = json.loads(actions_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise CliError(f"không đọc được actions.json của execution '{args.execution_id}': {exc}") from exc
        if not isinstance(actions_data, list) or not all(isinstance(item, dict) for item in actions_data):
            raise CliError(
                f"'{actions_path}' phải là 1 danh sách ActionSpec (JSON object) — file này có vẻ không "
                "phải actions.json do `execute` sinh ra."
            )
        try:
            actions = [ActionSpec(**item) for item in actions_data]
        except ValidationError as exc:
            raise CliError(f"không đọc được actions.json của execution '{args.execution_id}': {exc}") from exc

        control: Dict[str, Any] = {
            "execution_id": args.execution_id,
            "total_actions": len(actions),
            "actions_by_role": dict(Counter(a.role.value for a in actions)),
        }

        if args.allowed_action:
            authorization = _build_local_test_authorization(args)
            outside = [f"{a.method} {a.target}" for a in actions if not is_allowed(a, authorization).allowed]
            control["actions_outside_allowlist_count"] = len(outside)
            control["actions_outside_allowlist"] = outside
        else:
            control["actions_outside_allowlist_count"] = "N/A — không truyền --allowed-action"

        kill_switch_log_path = execution_dir / "kill_switch_audit_log.jsonl"
        kill_switch_events: List[dict] = []
        if kill_switch_log_path.exists():
            for line in kill_switch_log_path.read_text(encoding="utf-8").splitlines():
                if not line:
                    continue
                try:
                    kill_switch_events.append(json.loads(line))
                except json.JSONDecodeError:
                    # Best-effort report, not a recovery routine — skip a
                    # torn line rather than fail the whole measurement.
                    continue
        stop_events = [e for e in kill_switch_events if e.get("event") == "stop"]
        automatic_stops = [e for e in stop_events if e.get("source") == "automatic_threshold"]
        control["kill_switch"] = {
            "total_events": len(kill_switch_events),
            "stop_events": len(stop_events),
            "automatic_threshold_stops": len(automatic_stops),
            "automatic_threshold_reasons": dict(Counter(e.get("automatic_threshold_reason") for e in automatic_stops)),
        }

        cost_log_path = execution_dir / "cost_audit_log.jsonl"
        if cost_log_path.exists():
            cost_lines = [line for line in cost_log_path.read_text(encoding="utf-8").splitlines() if line]
            cap = None
            for line in reversed(cost_lines):
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "cap" in entry:
                    cap = entry["cap"]
                    break
            control["cost"] = {"executed_action_count": len(cost_lines), "cap": cap}
        else:
            control["cost"] = {
                "status": "N/A — không có cost_audit_log.jsonl (execution này chưa dùng Cost Service)"
            }

        report["control_effectiveness"] = control
    else:
        report["control_effectiveness"] = {"status": "N/A — không truyền --execution-id"}

    report["khả_năng_bàn_giao"] = {
        "status": "N/A — cần runbook/con người test thật (vd đưa package cho 1 người khác đọc và tự "
        "hành động theo), không tự động hoá được bằng CLI",
    }

    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    print("=== SPEC §8.1 — chỉ số đo được ===")
    sc = report["schema_completeness"]
    if "is_release_ready" in sc:
        suffix = f" (thiếu: {sc['missing_fields']})" if sc["missing_fields"] else ""
        print(f"1. Schema completeness: is_release_ready={sc['is_release_ready']}{suffix}")
    else:
        print(f"1. Schema completeness: {sc['status']}")
    print(f"2. ECS: {report['ecs']['status']}")
    rp = report["reproducibility"]
    if "status" in rp:
        print(f"3. Reproducibility: {rp['status']}")
    else:
        if "WARNING_mismatch_with_raw_artifact" in rp:
            mismatch_note = ", CÓ SAI LỆCH với raw artifact — xem stderr"
        elif "WARNING_could_not_cross_check_any_run" in rp:
            mismatch_note = ", CHƯA KIỂM CHỨNG ĐƯỢC — xem stderr"
        else:
            mismatch_note = ""
        print(
            f"3. Reproducibility: {rp['agreement_ratio']:.0%} ({rp['runs']} lần, verdict phổ biến nhất "
            f"'{rp['most_common_verdict']}') — đạt ngưỡng đề xuất >=2/3: {rp['meets_recommended_threshold']}, "
            f"đã đối chiếu raw artifact: {rp['cross_checked_against_raw_artifact']}/{rp['runs']} lần{mismatch_note}"
        )
    ce = report["control_effectiveness"]
    if "status" in ce:
        print(f"4. Control effectiveness: {ce['status']}")
    else:
        print(
            f"4. Control effectiveness (execution '{ce['execution_id']}'): {ce['total_actions']} action "
            f"({ce['actions_by_role']}), ngoài allowlist: {ce['actions_outside_allowlist_count']}, "
            f"kill-switch tự động: {ce['kill_switch']['automatic_threshold_stops']} lần, "
            f"cost: {ce['cost']}"
        )
    print(f"5. Khả năng bàn giao: {report['khả_năng_bàn_giao']['status']}")
    return 0
