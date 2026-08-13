import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import httpx

from context_store.store import DEFAULT_DB_PATH, SecurityContextStore
from exploit_agent.agent import ExploitAgent
from hypothesis_engine.engine import HypothesisEngine
from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from shared.id_generator import generate_id
from shared.models.action import ActionPlanStatus
from shared.models.entities import Authorization, AuthorizationLayer
from shared.models.hypothesis import Hypothesis, HypothesisProvenance, HypothesisStatus
from shared.models.signal import NormalizedSignal, SignalCoverage


def _print_skip_warning(message: str) -> None:
    print(f"CẢNH BÁO: {message}", file=sys.stderr)


def _load_signals(args: argparse.Namespace) -> Optional[List[NormalizedSignal]]:
    normalizer = SignalNormalizer()
    try:
        return normalizer.normalize_file(
            report_path=args.signal,
            tool=args.tool,
            tool_version=args.tool_version,
            coverage=SignalCoverage(args.coverage),
            on_skip=_print_skip_warning,
        )
    except FileNotFoundError:
        print(f"error: không tìm thấy file '{args.signal}'", file=sys.stderr)
        return None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None


def cmd_normalize(args: argparse.Namespace) -> int:
    signals = _load_signals(args)
    if signals is None:
        return 1

    if args.format == "json":
        payload = [json.loads(s.model_dump_json()) for s in signals]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"-> {len(signals)} NormalizedSignal từ '{args.signal}' (tool={args.tool})")
        for s in signals:
            print(
                f"  - {s.rule.id} | {s.severity.raw} -> {s.severity.normalized.value} "
                f"| cwe={s.rule.cwe or '-'} | location={s.location}"
            )

    return 0


def _build_llm_client(args: argparse.Namespace, agent_mode_message: str, api_mode_subject: str):
    """Dựng LLM client theo --llm-mode, in đúng cảnh báo tương ứng. Trả None
    (đã in lỗi ra stderr) nếu construct thất bại ở api mode (thiếu env var)."""
    if args.llm_mode == "agent":
        from hypothesis_engine.llm_client.agent_bridge_client import AgentBridgeLLMClient

        llm_client = AgentBridgeLLMClient()
        print(f"CẢNH BÁO: chế độ agent-bridge — không gọi API nào. {agent_mode_message}", file=sys.stderr)
        return llm_client

    from hypothesis_engine.llm_client.openai_compatible_client import OpenAICompatibleLLMClient

    try:
        llm_client = OpenAICompatibleLLMClient()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None
    print(
        f"CẢNH BÁO: sắp gửi {api_mode_subject} tới LLM thật (model={llm_client.model}).",
        file=sys.stderr,
    )
    return llm_client


def cmd_hypothesize(args: argparse.Namespace) -> int:
    signals = _load_signals(args)
    if signals is None:
        return 1

    source_snippet = None
    if args.source:
        try:
            source_snippet = Path(args.source).read_text()
        except FileNotFoundError:
            print(f"error: không tìm thấy source file '{args.source}'", file=sys.stderr)
            return 1

    try:
        context_store = SecurityContextStore(db_path=args.context_db)
    except sqlite3.Error as exc:
        print(f"error: không mở được Context Store tại '{args.context_db}': {exc}", file=sys.stderr)
        return 1

    results: List[tuple] = []
    failure: Optional[str] = None
    try:
        verified_context = (
            context_store.get_verified_context(args.target_id) if args.target_id else []
        )

        llm_client = _build_llm_client(
            args,
            agent_mode_message=(
                f"Toàn bộ {len(signals)} signal sẽ gộp vào 1 file prompt, bạn chỉ cần nhờ "
                "agent (Claude Code) xử lý và chờ Enter đúng 1 lần."
            ),
            api_mode_subject="NormalizedSignal (và source code nếu có)",
        )
        if llm_client is None:
            return 1

        engine = HypothesisEngine(llm_client)

        if args.llm_mode == "agent":
            # Gộp tất cả signal vào đúng 1 vòng hỏi-đáp thay vì lặp lại "ghi
            # prompt -> chờ Enter" cho từng signal riêng lẻ — xây hết prompt
            # trước, gọi generate_many() một lần, rồi parse lại từng response.
            prompts = [
                engine.build_prompt(signal, source_snippet, verified_context)
                for signal in signals
            ]
            try:
                raw_responses = llm_client.generate_many(prompts)
            except RuntimeError as exc:
                failure = str(exc)
                raw_responses = []
            for signal, raw in zip(signals, raw_responses):
                try:
                    result = engine.parse_response(raw, signal)
                    context_store.record_hypothesis(result, signal)
                except RuntimeError as exc:
                    failure = str(exc)
                    break
                results.append((signal, result))
        else:
            # Ghi lại NGAY từng hypothesis vừa sinh thành công (không gom hết
            # vào 1 list rồi mới ghi) — nếu 1 signal giữa chừng lỗi (mất mạng,
            # hết quota), các hypothesis đã trả tiền/thời gian để sinh trước đó
            # vẫn được giữ lại, không bị vứt bỏ theo kiểu tất-cả-hoặc-không-gì.
            for signal in signals:
                try:
                    result = engine.generate_hypothesis(
                        signal, source_snippet=source_snippet, verified_context=verified_context
                    )
                    context_store.record_hypothesis(result, signal)
                except (RuntimeError, httpx.HTTPError) as exc:
                    failure = str(exc)
                    break
                results.append((signal, result))
    finally:
        context_store.close()

    if args.format == "json":
        payload = [
            {
                "signal_id": signal.signal_id,
                "rule_id": signal.rule.id,
                "result": json.loads(result.model_dump_json()),
            }
            for signal, result in results
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"-> {len(results)} hypothesis result(s) từ '{args.signal}'")
        for signal, result in results:
            if result.status == HypothesisStatus.HYPOTHESIS:
                print(f"  [{signal.rule.id}] HYPOTHESIS ({result.hypothesis.hypothesis_id})")
                provenance = result.hypothesis.provenance
                print(f"    Expected behavior   : {result.hypothesis.expected_behavior}")
                print(f"    Suspected behavior  : {result.hypothesis.suspected_behavior}")
                print(f"    Observation criteria: {result.hypothesis.observation_criteria}")
                print(
                    f"    Provenance          : source_tool={provenance.source_tool}, "
                    f"source_signal_id={provenance.source_signal_id}, coverage={provenance.coverage.value}"
                )
            else:
                print(f"  [{signal.rule.id}] NOT_VERIFIABLE — {result.reason}")

    if failure:
        print(f"error: {failure}", file=sys.stderr)
        return 1

    return 0


def _print_hypothesis_record(record: dict) -> None:
    print(f"hypothesis_id       : {record['hypothesis_id']}")
    print(f"signal_id           : {record['signal_id']}")
    print(f"source_tool         : {record['source_tool']}")
    print(f"status              : {record['status']}")
    print(f"coverage            : {record['coverage']}")
    print(f"location            : {record['location']}")
    print(f"created_at          : {record['created_at']}")
    print(f"expected_behavior   : {record['expected_behavior']}")
    print(f"suspected_behavior  : {record['suspected_behavior']}")
    print(f"observation_criteria: {record['observation_criteria']}")
    print(f"reason              : {record['reason']}")


def cmd_show_hypothesis(args: argparse.Namespace) -> int:
    try:
        context_store = SecurityContextStore(db_path=args.context_db)
    except sqlite3.Error as exc:
        print(f"error: không mở được Context Store tại '{args.context_db}': {exc}", file=sys.stderr)
        return 1

    try:
        if args.hypothesis_id:
            record = context_store.get_hypothesis(args.hypothesis_id)
            records = [record] if record is not None else []
        else:
            # hypothesis_id chỉ tồn tại khi status=hypothesis — bản ghi
            # NOT_VERIFIABLE (không có Hypothesis nào được tạo) chỉ tra được
            # qua signal_id, không có hypothesis_id để tra.
            records = context_store.get_hypotheses_by_signal_id(args.signal_id)
    finally:
        context_store.close()

    if not records:
        key = f"hypothesis_id '{args.hypothesis_id}'" if args.hypothesis_id else f"signal_id '{args.signal_id}'"
        print(f"error: không tìm thấy bản ghi nào cho {key}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(records if args.signal_id else records[0], indent=2, ensure_ascii=False))
    else:
        for i, record in enumerate(records):
            if i > 0:
                print()
            _print_hypothesis_record(record)

    return 0


def _load_stored_hypothesis(record: dict) -> Hypothesis:
    if record["location"] is None:
        raise ValueError(
            f"hypothesis_id '{record['hypothesis_id']}' được lưu trước khi Context Store có field "
            "'location' (bản ghi cũ) — chạy lại 'hypothesize' cho signal gốc để sinh hypothesis mới "
            "đủ thông tin cho 'plan'."
        )
    return Hypothesis(
        hypothesis_id=record["hypothesis_id"],
        expected_behavior=record["expected_behavior"],
        suspected_behavior=record["suspected_behavior"],
        observation_criteria=record["observation_criteria"],
        provenance=HypothesisProvenance(
            source_tool=record["source_tool"],
            source_signal_id=record["signal_id"],
            coverage=SignalCoverage(record["coverage"]),
            location=json.loads(record["location"]),
        ),
    )


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        context_store = SecurityContextStore(db_path=args.context_db)
    except sqlite3.Error as exc:
        print(f"error: không mở được Context Store tại '{args.context_db}': {exc}", file=sys.stderr)
        return 1

    try:
        record = context_store.get_hypothesis(args.hypothesis_id)
    finally:
        context_store.close()

    if record is None:
        print(
            f"error: không tìm thấy hypothesis_id '{args.hypothesis_id}' (chỉ tra được bản ghi "
            "status=hypothesis, không tra được not_verifiable)",
            file=sys.stderr,
        )
        return 1

    try:
        hypothesis = _load_stored_hypothesis(record)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    llm_client = _build_llm_client(
        args,
        agent_mode_message="Nhờ agent (Claude Code) đọc file prompt và trả JSON, rồi chờ Enter đúng 1 lần.",
        api_mode_subject="Hypothesis",
    )
    if llm_client is None:
        return 1

    agent = ExploitAgent(llm_client)

    try:
        plan_result = agent.plan(hypothesis)
    except (RuntimeError, httpx.HTTPError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    review = None
    if plan_result.status == ActionPlanStatus.PLANNED:
        print(
            "CẢNH BÁO: authorization dùng để check dưới đây CHỈ dựng tạm để test cục bộ từ "
            "--allowed-action — KHÔNG phải Gate 2/3 thật đã duyệt, không dùng để chạy hành động "
            "thật lên bất kỳ hệ thống nào.",
            file=sys.stderr,
        )
        authorization = Authorization(
            id=generate_id("auth"),
            layer=AuthorizationLayer.TARGET_AUTHORIZATION,
            approved_by="cli-local-test",
            approved_at=datetime.now(timezone.utc),
            allowed_actions=args.allowed_action or [],
        )
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


def _add_report_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--signal", required=True, help="Đường dẫn tới report JSON thô")
    parser.add_argument("--tool", required=True, choices=["semgrep", "trivy", "owasp_zap"])
    parser.add_argument("--tool-version", required=True, help="Version của tool đã sinh report")
    parser.add_argument("--coverage", default="unknown", choices=["complete", "partial", "unknown"])


def _add_context_db_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--context-db", default=DEFAULT_DB_PATH, help="Đường dẫn file SQLite Context Store (mặc định: %(default)s)"
    )


def _add_llm_mode_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--llm-mode",
        default="api",
        choices=["api", "agent"],
        help="api (mặc định, cần LLM_API_KEY/LLM_BASE_URL/LLM_MODEL) | "
        "agent (không cần API key, bắc cầu qua file để agent đang chat xử lý)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secweave", description="SecWeave controlled verification toolkit (MVP)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize_parser = subparsers.add_parser(
        "normalize",
        help="Chuẩn hoá 1 report thô (Semgrep/Trivy/OWASP ZAP) thành NormalizedSignal",
    )
    _add_report_args(normalize_parser)
    normalize_parser.add_argument("--format", default="table", choices=["table", "json"])
    normalize_parser.set_defaults(func=cmd_normalize)

    hypothesize_parser = subparsers.add_parser(
        "hypothesize",
        help="Sinh Hypothesis từ 1 report thô — dùng LLM API thật, hoặc bắc cầu qua agent (--llm-mode)",
    )
    _add_report_args(hypothesize_parser)
    hypothesize_parser.add_argument("--source", help="Đường dẫn file source code liên quan (tuỳ chọn)")
    hypothesize_parser.add_argument("--target-id", help="target_id để tra verified context (tuỳ chọn)")
    _add_llm_mode_arg(hypothesize_parser)
    hypothesize_parser.add_argument("--format", default="table", choices=["table", "json"])
    _add_context_db_arg(hypothesize_parser)
    hypothesize_parser.set_defaults(func=cmd_hypothesize)

    plan_parser = subparsers.add_parser(
        "plan",
        help="Soạn Action Plan từ 1 Hypothesis đã lưu, rồi check qua Policy/Cost Service (chưa thực thi)",
    )
    plan_parser.add_argument(
        "--hypothesis-id", required=True, help="hypothesis_id đã lưu trong Context Store (từ `hypothesize`)"
    )
    plan_parser.add_argument(
        "--allowed-action",
        action="append",
        help='1 entry allowlist, dạng "METHOD https://host/path/{param}" — có thể lặp lại flag này '
        "nhiều lần để cấp nhiều entry. Không truyền = allowlist rỗng = mọi action đều bị chặn.",
    )
    plan_parser.add_argument(
        "--cap", type=int, default=10, help="Cap số hành động dự kiến tối đa trong plan (mặc định: %(default)s)"
    )
    _add_llm_mode_arg(plan_parser)
    plan_parser.add_argument("--format", default="table", choices=["table", "json"])
    _add_context_db_arg(plan_parser)
    plan_parser.set_defaults(func=cmd_plan)

    show_hypothesis_parser = subparsers.add_parser(
        "show-hypothesis",
        help="Tra cứu lại (các) hypothesis đã sinh trước đó, theo hypothesis_id hoặc signal_id",
    )
    show_hypothesis_group = show_hypothesis_parser.add_mutually_exclusive_group(required=True)
    show_hypothesis_group.add_argument(
        "--hypothesis-id", help="Tra đúng 1 hypothesis (chỉ có ở bản ghi status=hypothesis)"
    )
    show_hypothesis_group.add_argument(
        "--signal-id",
        help="Tra tất cả bản ghi (kể cả not_verifiable) sinh ra từ 1 signal_id",
    )
    show_hypothesis_parser.add_argument("--format", default="table", choices=["table", "json"])
    _add_context_db_arg(show_hypothesis_parser)
    show_hypothesis_parser.set_defaults(func=cmd_show_hypothesis)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    # Chỉ tự nạp .env khi chạy CLI thật (python cli.py ...), KHÔNG nạp khi
    # cli.main() được gọi trực tiếp từ test — nếu không, 1 file .env thật nằm
    # sẵn trên máy dev sẽ âm thầm phá test đang cố mô phỏng "thiếu env var".
    from dotenv import load_dotenv

    load_dotenv()
    raise SystemExit(main())
