import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

import httpx

from context_store.store import SecurityContextStore
from hypothesis_engine.engine import HypothesisEngine
from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from shared.models.hypothesis import HypothesisStatus
from shared.models.signal import SignalCoverage


def cmd_normalize(args: argparse.Namespace) -> int:
    normalizer = SignalNormalizer()
    try:
        signals = normalizer.normalize_file(
            report_path=args.signal,
            tool=args.tool,
            tool_version=args.tool_version,
            coverage=SignalCoverage(args.coverage),
        )
    except FileNotFoundError:
        print(f"error: không tìm thấy file '{args.signal}'", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyError as exc:
        print(f"error: report thiếu field bắt buộc: {exc}", file=sys.stderr)
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


def cmd_hypothesize(args: argparse.Namespace) -> int:
    normalizer = SignalNormalizer()
    try:
        signals = normalizer.normalize_file(
            report_path=args.signal,
            tool=args.tool,
            tool_version=args.tool_version,
            coverage=SignalCoverage(args.coverage),
        )
    except FileNotFoundError:
        print(f"error: không tìm thấy file '{args.signal}'", file=sys.stderr)
        return 1
    except (ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    source_snippet = None
    if args.source:
        try:
            source_snippet = Path(args.source).read_text()
        except FileNotFoundError:
            print(f"error: không tìm thấy source file '{args.source}'", file=sys.stderr)
            return 1

    context_store = SecurityContextStore()
    verified_context = (
        context_store.get_verified_context(args.target_id) if args.target_id else []
    )
    context_store.close()

    if args.llm_mode == "agent":
        from hypothesis_engine.llm_client.agent_bridge_client import AgentBridgeLLMClient

        llm_client = AgentBridgeLLMClient()
        print(
            "CẢNH BÁO: chế độ agent-bridge — không gọi API nào, prompt sẽ được ghi ra "
            "file để bạn nhờ agent (Claude Code) xử lý thủ công từng signal.",
            file=sys.stderr,
        )
    else:
        from hypothesis_engine.llm_client.openai_compatible_client import OpenAICompatibleLLMClient

        try:
            llm_client = OpenAICompatibleLLMClient()
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(
            f"CẢNH BÁO: sắp gửi NormalizedSignal (và source code nếu có) tới LLM thật "
            f"(model={llm_client.model}).",
            file=sys.stderr,
        )

    engine = HypothesisEngine(llm_client)
    try:
        results = [
            (
                signal,
                engine.generate_hypothesis(
                    signal, source_snippet=source_snippet, verified_context=verified_context
                ),
            )
            for signal in signals
        ]
    except (RuntimeError, httpx.HTTPError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

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
                print(f"  [{signal.rule.id}] HYPOTHESIS")
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

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secweave", description="SecWeave controlled verification toolkit (MVP)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize_parser = subparsers.add_parser(
        "normalize",
        help="Chuẩn hoá 1 report thô (Semgrep/Trivy/OWASP ZAP) thành NormalizedSignal",
    )
    normalize_parser.add_argument("--signal", required=True, help="Đường dẫn tới report JSON thô")
    normalize_parser.add_argument(
        "--tool", required=True, choices=["semgrep", "trivy", "owasp_zap"]
    )
    normalize_parser.add_argument(
        "--tool-version", required=True, help="Version của tool đã sinh report"
    )
    normalize_parser.add_argument(
        "--coverage", default="unknown", choices=["complete", "partial", "unknown"]
    )
    normalize_parser.add_argument("--format", default="table", choices=["table", "json"])
    normalize_parser.set_defaults(func=cmd_normalize)

    hypothesize_parser = subparsers.add_parser(
        "hypothesize",
        help="Sinh Hypothesis từ 1 report thô — dùng LLM API thật, hoặc bắc cầu qua agent (--llm-mode)",
    )
    hypothesize_parser.add_argument("--signal", required=True, help="Đường dẫn tới report JSON thô")
    hypothesize_parser.add_argument(
        "--tool", required=True, choices=["semgrep", "trivy", "owasp_zap"]
    )
    hypothesize_parser.add_argument(
        "--tool-version", required=True, help="Version của tool đã sinh report"
    )
    hypothesize_parser.add_argument(
        "--coverage", default="unknown", choices=["complete", "partial", "unknown"]
    )
    hypothesize_parser.add_argument("--source", help="Đường dẫn file source code liên quan (tuỳ chọn)")
    hypothesize_parser.add_argument("--target-id", help="target_id để tra verified context (tuỳ chọn)")
    hypothesize_parser.add_argument(
        "--llm-mode",
        default="api",
        choices=["api", "agent"],
        help="api (mặc định, cần LLM_API_KEY/LLM_BASE_URL/LLM_MODEL) | "
        "agent (không cần API key, bắc cầu qua file để agent đang chat xử lý)",
    )
    hypothesize_parser.add_argument("--format", default="table", choices=["table", "json"])
    hypothesize_parser.set_defaults(func=cmd_hypothesize)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
