import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

import httpx

from cli.common import CliError, _build_llm_client, _load_signals, _open_context_store
from hypothesis_engine.engine import HypothesisEngine
from shared.models.hypothesis import HypothesisStatus


def cmd_hypothesize(args: argparse.Namespace) -> int:
    try:
        return _run_hypothesize(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_hypothesize(args: argparse.Namespace) -> int:
    if args.target_id and not args.target_revision_id:
        raise CliError(
            "--target-revision-id là bắt buộc khi có --target-id — Context Store cần biết revision "
            "HIỆN TẠI của target để lọc đúng context còn hợp lệ, không trả nhầm context của 1 revision "
            "đã cũ (SPEC §4.6 staleness)."
        )
    signals = _load_signals(args)

    source_snippet = None
    if args.source:
        try:
            # encoding="utf-8" explicit — read_text() otherwise defaults to
            # the OS locale, which a minimal container may not set to UTF-8.
            source_snippet = Path(args.source).read_text(encoding="utf-8")
        except FileNotFoundError:
            raise CliError(f"không tìm thấy source file '{args.source}'")
        except OSError as exc:
            # Covers --source pointing at a directory (IsADirectoryError) or
            # an unreadable file (PermissionError), not just a missing one.
            raise CliError(f"không đọc được source file '{args.source}': {exc}") from exc
        except UnicodeDecodeError as exc:
            # A binary/non-UTF8 file is equally realistic --source misuse
            # (e.g. accidentally pointing at a compiled artifact) and isn't
            # an OSError, so needs its own clean handling.
            raise CliError(f"source file '{args.source}' không phải text UTF-8: {exc}") from exc

    context_store = _open_context_store(args.context_db)

    try:
        verified_context = (
            context_store.get_verified_context(args.target_id, args.target_revision_id)
            if args.target_id
            else []
        )
        # SPEC §4.6: "unverified: chỉ tra cứu, có nhãn cảnh báo" —
        # build_prompt() labels this separately from verified_context so
        # the LLM can't mistake "captured once, never reviewed" for
        # confirmed fact.
        unverified_context = (
            context_store.get_unverified_context(args.target_id, args.target_revision_id)
            if args.target_id
            else []
        )
    except RuntimeError as exc:
        # A real sqlite failure here (e.g. lock contention) must not dump a
        # raw traceback instead of this command's clean error contract.
        context_store.close()
        raise CliError(str(exc)) from exc

    results: List[tuple] = []
    failure: Optional[str] = None
    try:
        llm_client = _build_llm_client(
            args,
            agent_mode_message=(
                f"Toàn bộ {len(signals)} signal sẽ gộp vào 1 file prompt, bạn chỉ cần nhờ "
                "agent (Claude Code) xử lý và chờ Enter đúng 1 lần."
            ),
            api_mode_subject="NormalizedSignal (và source code nếu có)",
        )

        engine = HypothesisEngine(llm_client)

        if args.llm_mode == "agent":
            # Merge all signals into exactly 1 question-answer round instead
            # of repeating "write prompt -> wait for Enter" for each signal
            # individually — build all the prompts first, call
            # generate_many() once, then parse each response.
            prompts = [
                engine.build_prompt(signal, source_snippet, verified_context, unverified_context)
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
                    context_store.record_hypothesis(
                        result, signal, target_id=args.target_id, revision=args.target_revision_id
                    )
                except RuntimeError as exc:
                    failure = str(exc)
                    break
                results.append((signal, result))
        else:
            # Record each hypothesis IMMEDIATELY after it's generated (not
            # collected into a list and written at the end) — if a signal in
            # the middle fails (network loss, quota exhausted), the
            # hypotheses already paid for/generated before it are still kept,
            # not thrown away in an all-or-nothing fashion.
            for signal in signals:
                try:
                    result = engine.generate_hypothesis(
                        signal,
                        source_snippet=source_snippet,
                        verified_context=verified_context,
                        unverified_context=unverified_context,
                    )
                    context_store.record_hypothesis(
                        result, signal, target_id=args.target_id, revision=args.target_revision_id
                    )
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
