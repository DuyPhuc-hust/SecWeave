import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple

from cli.commands.execute import _run_execute
from cli.common import CliError, _read_verdict_for_execution
from shared.id_generator import generate_id


def cmd_retest(args: argparse.Namespace) -> int:
    """SPEC §8.1 (reproducibility) + WEEKLY_PLAN W7: chạy lại ĐÚNG 1 plan đã
    đóng băng (`--plan-file`, bắt buộc — khác `execute`, nơi nó là tuỳ
    chọn) `--runs` lần độc lập, mỗi lần 1 execution_id riêng (KHÔNG dùng
    chung kill-switch/cost giữa các lần — muốn đo khả năng lặp lại của hệ
    thống, không phải cộng dồn ngân sách 1 lượt chạy dài). `--plan-file`
    bắt buộc vì lý do khác `execute`: nếu để LLM tự lập lại plan mỗi lần,
    một verdict khác nhau giữa các lần có thể chỉ vì LLM không tất định
    (lập plan khác nhau), không nói lên được gì về khả năng lặp lại THẬT
    của hệ thống trên cùng 1 kịch bản — đúng câu hỏi §8.1 muốn đo.

    In ra TOÀN BỘ verdict của từng lần — không có đường nào để chỉ báo cáo
    lần "đẹp nhất" (WEEKLY_PLAN W7: "đây là hành vi bị cấm, tương đương
    gian lận bằng chứng"). Lưu 1 file tóm tắt JSON tại
    `{storage_dir}/{base_execution_id}_retest_summary.json` — id của file
    này (hoặc `retest_id` bên trong) là thứ nên truyền cho `review-package
    --retest-reference` sau đó.
    """
    try:
        return _run_retest(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_retest(args: argparse.Namespace) -> int:
    if not args.plan_file:
        raise CliError(
            "retest bắt buộc phải có --plan-file — chạy lại 1 plan LLM tự lập MỚI mỗi lần sẽ lẫn lộn "
            "'hệ thống có lặp lại được không' với 'LLM có lặp lại được không', 2 câu hỏi khác nhau."
        )
    if args.runs < 2:
        raise CliError(
            f"--runs={args.runs} không hợp lệ — cần >= 2 để đo tỷ lệ lặp lại có ý nghĩa (SPEC §8.1 đề "
            "xuất tối thiểu 3 lần; 1 lần chạy không nói lên được gì về khả năng lặp lại)."
        )

    base_execution_id = args.execution_id or generate_id("exec")
    print(f"-> retest {args.runs} lần độc lập cho plan '{args.plan_file}', base execution_id='{base_execution_id}'")

    results: List[Tuple[str, Optional[str]]] = []
    corrupted_artifact_count = 0
    for i in range(1, args.runs + 1):
        run_execution_id = f"{base_execution_id}_retest{i}"
        # A shallow copy per run — only .execution_id differs, everything
        # else (plan-file, allowlist, identity config, cap, target...) is
        # IDENTICAL across all runs, on purpose (that's the whole point of
        # a reproducibility test: same inputs, does the SAME thing happen
        # again).
        run_args = argparse.Namespace(**vars(args))
        run_args.execution_id = run_execution_id
        print(f"\n===== Lần {i}/{args.runs} (execution_id='{run_execution_id}') =====")
        try:
            _run_execute(run_args)
        except CliError as exc:
            # A single run's own setup failure (bad --identity-logins,
            # malformed --plan-file, etc.) would hit every subsequent run
            # identically — failing the whole batch immediately is more
            # honest than silently reporting on however many runs
            # happened to complete before hitting the same root cause.
            raise CliError(f"retest dừng ở lần {i}/{args.runs}: {exc}") from exc
        try:
            verdict = _read_verdict_for_execution(run_execution_id, args.storage_dir)
        except CliError as exc:
            # Guarded separately from _run_execute() above: a
            # corrupted/torn observations.jsonl line (a realistic outcome
            # of a crash mid-write) must not abort the WHOLE retest batch
            # and discard the verdicts of every PRIOR run, even though
            # those runs already sent real HTTP requests and consumed
            # real cost-cap budget. Unlike _run_execute()'s own setup
            # failure above (which genuinely hits every subsequent run
            # identically), a corrupted artifact is per-run I/O — only
            # THIS run's verdict is unreadable, not a reason to discard
            # every other run's real result. Tracked separately from
            # `runs_with_no_verdict` (a legitimately-stopped run) since
            # "verdict unreadable due to corruption" is a more concerning
            # finding than "run never captured anything."
            verdict = None
            corrupted_artifact_count += 1
            print(f"   CẢNH BÁO: không đọc được verdict của lần {i}/{args.runs}: {exc}", file=sys.stderr)
        results.append((run_execution_id, verdict))
        print(f"-> Lần {i}/{args.runs}: verdict={verdict or '(không có observation — có thể đã bị dừng giữa chừng)'}")

    verdict_counts = Counter(v for _, v in results if v is not None)
    most_common_verdict, agree_count = verdict_counts.most_common(1)[0] if verdict_counts else (None, 0)
    ratio = agree_count / len(results)
    meets_threshold = ratio >= (2 / 3)
    # Surfaced separately from agreement_ratio — a run stopped by an
    # unrelated kill-switch/cost-cap trigger (verdict=None) would otherwise
    # look identical to one that genuinely produced a different verdict,
    # misreading infra noise as the system being non-deterministic.
    no_verdict_count = sum(1 for _, v in results if v is None)

    summary = {
        "retest_id": generate_id("retest"),
        "base_execution_id": base_execution_id,
        "runs": args.runs,
        "results": [{"execution_id": eid, "verdict": v} for eid, v in results],
        "most_common_verdict": most_common_verdict,
        "agreement_count": agree_count,
        "agreement_ratio": ratio,
        "meets_recommended_threshold": meets_threshold,
        "runs_with_no_verdict": no_verdict_count,
        "runs_with_corrupted_artifact": corrupted_artifact_count,
    }
    summary_path = Path(args.storage_dir) / f"{base_execution_id}_retest_summary.json"
    try:
        # mkdir needed explicitly: if every run got BLOCKED before
        # EvidenceHarness was ever constructed, nothing else creates
        # --storage-dir (that's normally EvidenceHarness.__init__'s job).
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        # A disk-full/permission failure here happens AFTER every retest
        # run already completed real HTTP requests — must not swallow the
        # agreement-ratio printout below with a raw traceback.
        raise CliError(f"không ghi được '{summary_path}': {type(exc).__name__}: {exc}") from exc

    print(f"\n-> Tỷ lệ cùng verdict: {agree_count}/{len(results)} ({ratio:.0%}) — verdict phổ biến nhất: "
          f"{most_common_verdict or '(không lần nào có verdict)'}")
    if no_verdict_count:
        print(
            f"-> LƯU Ý: {no_verdict_count}/{len(results)} lần KHÔNG có verdict nào (dừng giữa chừng do "
            "kill-switch/cost-cap hoặc lỗi hạ tầng khác) — tỷ lệ trên có thể phản ánh sự cố hạ tầng, "
            "không hẳn là hệ thống thiếu tất định. Xem 'results' để biết chính xác lần nào."
        )
    if corrupted_artifact_count:
        print(
            f"-> CẢNH BÁO: {corrupted_artifact_count}/{len(results)} lần có artifact BỊ HỎNG, không đọc "
            "lại được verdict dù request thật đã gửi và tốn cost-cap thật — khác với 'dừng giữa chừng "
            "bình thường', đây là dấu hiệu cần kiểm tra thủ công (đĩa hỏng, ghi đè tay, ...), không nên "
            "âm thầm coi là 1 lần 'không có verdict' thông thường."
        )
    print(f"-> Ngưỡng đề xuất SPEC §8.1 (>= 2/3): {'ĐẠT' if meets_threshold else 'CHƯA ĐẠT — phải ghi vào Limitations'}")
    print(f"-> retest_id: {summary['retest_id']} — lưu tóm tắt tại: {summary_path}")

    if args.format == "json":
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0
