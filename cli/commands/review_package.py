import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from cli.common import CliError, _open_context_store, _parse_enum_arg
from shared.models.observation import NormalizedObservation
from shared.models.verification_package import ReviewDecision, VerificationPackage
from verdict_oracle.predicates import evaluate_predicates


def cmd_review_package(args: argparse.Namespace) -> int:
    """Gate 4 — Human Review Loop tối thiểu (SPEC §4.5). Đọc lại 1
    VerificationPackage đã lắp (`secweave assemble-package --format json`),
    gắn `HumanReviewRecord` do người review cung cấp, in lại package đã
    cập nhật. Đây là bản tối thiểu — chưa có UI, chưa tự động hoá gì cả,
    đúng chủ đích: SPEC bắt buộc con người tự tay đối chiếu raw artifact,
    không phải thứ CLI có thể làm thay.

    Ràng buộc cứng của SPEC §4.5 được giữ bằng THIẾT KẾ ở phần lớn field
    (không flag nào cho sửa `raw_evidence_references`/`artifact_hashes`/
    `normalized_observations`/`action_record` — chỉ đọc lại nguyên trạng từ
    file). Nhưng `predicate_results`/`verdict` chính chúng lại NẰM SẴN
    trong file, nên phải tính lại `evaluate_predicates()` trên đúng
    `normalized_observations` trong file rồi so với `predicate_results` đã
    khai — lệch là từ chối: 1 file bị sửa tay để fabricate verdict+predicate
    khớp nhau về nội bộ nhưng không khớp observation thật sẽ không qua
    được validator nào nếu chỉ kiểm tính nhất quán nội bộ.
    """
    try:
        return _run_review_package(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_review_package(args: argparse.Namespace) -> int:
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

    decision = _parse_enum_arg(ReviewDecision, args.decision, "--decision")

    if args.retest_reference and decision != ReviewDecision.RETEST:
        # --retest-reference with a non-retest decision would attach field
        # #19 ("absent until retests have run") to a package where no retest
        # actually happened.
        raise CliError(
            f"--retest-reference chỉ hợp lệ cùng --decision retest (đang dùng --decision {decision.value})."
        )

    try:
        observations_for_check = [NormalizedObservation(**o) for o in package_data.get("normalized_observations", [])]
        declared_results = {
            (r["group"], r["status"]) for r in package_data.get("predicate_results", [])
        }
        recomputed_results = {
            (r.group.value, r.status.value) for r in evaluate_predicates(observations_for_check)
        }
    except (ValidationError, KeyError, TypeError) as exc:
        raise CliError(f"không đọc được normalized_observations/predicate_results trong file: {exc}") from exc
    if declared_results != recomputed_results:
        # Every other validator here only checks INTERNAL consistency
        # (e.g. "CONFIRMED requires all 3 groups satisfied"), never that
        # predicate_results actually reflects normalized_observations — so
        # a hand-edited file with a fabricated but internally-consistent
        # verdict+predicate_results, left next to untouched (unsatisfying)
        # observations, would otherwise pass. A real assemble-package run
        # always produces a package where these agree.
        raise CliError(
            "predicate_results trong file KHÔNG khớp với normalized_observations thật — package này có "
            "dấu hiệu bị sửa tay sau khi `assemble-package` chạy, từ chối review."
        )

    # SPEC §4.5 bước 1: "Đối chiếu ít nhất một raw artifact với normalized
    # observation" — CLI không tự làm thay được (đây đúng là việc chỉ con
    # người mới làm được), nhưng in sẵn danh sách ra để reviewer thực sự có
    # thứ để đối chiếu ngay trên màn hình, thay vì chỉ tin lời khai
    # --checked-raw-artifact.
    raw_refs = package_data.get("raw_evidence_references", [])
    print(f"-> {len(raw_refs)} raw evidence reference cần đối chiếu trước khi quyết định:", file=sys.stderr)
    for ref in raw_refs:
        print(f"     {ref}", file=sys.stderr)

    existing_review = package_data.get("human_review_record")
    if existing_review:
        # Not blocked outright — a legitimate re-review after a rejected
        # package gets fixed and reassembled is a real workflow — but
        # surfaced loudly so a prior reviewer's decision isn't silently
        # overwritten without a trace.
        print(
            f"CẢNH BÁO: đang GHI ĐÈ 1 human_review_record đã có — reviewer trước: "
            f"'{existing_review.get('reviewer')}', decision trước: '{existing_review.get('decision')}', "
            f"lý do trước: '{existing_review.get('reason')}'.",
            file=sys.stderr,
        )

    review_record = {
        "reviewer": args.reviewer,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "decision": decision.value,
        "reason": args.reason,
        "checked_raw_artifact": args.checked_raw_artifact,
    }
    package_data["human_review_record"] = review_record
    if args.retest_reference:
        package_data["retest_reference"] = args.retest_reference

    try:
        # Rebuilt from the whole dict, not model_copy(update=...) — the
        # latter doesn't re-run validators, and every validator (including
        # HumanReviewRecord's own decision=release/checked_raw_artifact
        # check) must run again against the fully updated data.
        package = VerificationPackage(**package_data)
    except ValidationError as exc:
        raise CliError(f"không gắn được human_review_record vào package: {exc}") from exc

    if decision == ReviewDecision.RELEASE:
        # SPEC §4.6 write path: "Human Review -- phát hành package ->
        # chuyển verified --> Context Store" — only a released package
        # promotes anything.
        promotion_context_store = _open_context_store(args.context_db)
        try:
            promoted = promotion_context_store.promote_execution_to_verified(
                execution_id=package.execution_id, package_id=package.package_id
            )
        except RuntimeError as exc:
            raise CliError(str(exc)) from exc
        finally:
            promotion_context_store.close()
        print(f"-> Đã promote {promoted} observation sang verified trong Context Store.", file=sys.stderr)

    if args.format == "json":
        print(package.model_dump_json(indent=2))
    else:
        print(f"package_id: {package.package_id}")
        print(f"decision: {package.human_review_record.decision.value} — {package.human_review_record.reason}")
        missing = package.missing_fields_for_release()
        print(f"is_release_ready: {package.is_release_ready}" + (f" (thiếu: {missing})" if missing else ""))
    return 0
