import argparse
import json
import sys

import httpx

from cli.common import (
    CliError,
    _build_llm_client,
    _build_local_test_authorization,
    _load_hypothesis_from_context_store,
    _open_context_store,
)
from exploit_agent.agent import ExploitAgent
from shared.models.action import ActionPlanStatus


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        return _run_plan(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_plan(args: argparse.Namespace) -> int:
    context_store = _open_context_store(args.context_db)
    hypothesis = _load_hypothesis_from_context_store(
        context_store, args.hypothesis_id, args.target_id, args.target_revision_id
    )

    llm_client = _build_llm_client(
        args,
        agent_mode_message="Nhờ agent (Claude Code) đọc file prompt và trả JSON, rồi chờ Enter đúng 1 lần.",
        api_mode_subject="Hypothesis",
    )

    agent = ExploitAgent(llm_client)

    try:
        plan_result = agent.plan(hypothesis)
    except (RuntimeError, httpx.HTTPError) as exc:
        raise CliError(str(exc)) from exc

    review = None
    if plan_result.status == ActionPlanStatus.PLANNED:
        print(
            "CẢNH BÁO: authorization dùng để check dưới đây CHỈ dựng tạm để test cục bộ từ "
            "--allowed-action — KHÔNG phải Gate 2/3 thật đã duyệt, không dùng để chạy hành động "
            "thật lên bất kỳ hệ thống nào.",
            file=sys.stderr,
        )
        authorization = _build_local_test_authorization(args)
        review = agent.review_plan(plan_result.plan, authorization, cap=args.cap)

    if args.format == "json":
        payload = {
            "hypothesis_id": args.hypothesis_id,
            "plan_result": json.loads(plan_result.model_dump_json()),
            "review": json.loads(review.model_dump_json()) if review else None,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    if plan_result.status == ActionPlanStatus.NOT_PLANNABLE:
        print(f"NOT_PLANNABLE — {plan_result.reason}")
        return 0

    print(f"-> ActionPlan cho hypothesis '{args.hypothesis_id}' ({len(plan_result.plan.actions)} action):")
    for check in review.plan_check.checks:
        verdict = "PASS" if check.decision.allowed else "FAIL"
        print(f"  [{verdict}] {check.action.method} {check.action.target} ({check.action.type.value})")
        print(f"         {check.action.description}")
        print(f"         Policy: {check.decision.reason}")
    print(
        f"-> Cost: {review.cost_check.planned_action_count}/{review.cost_check.cap} — "
        f"{'OK' if review.cost_check.allowed else 'VƯỢT CAP'}"
    )
    print(f"-> Kết quả tổng: {'APPROVED' if review.approved else 'BLOCKED'}")

    return 0
