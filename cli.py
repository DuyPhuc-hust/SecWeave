import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional, Type, TypeVar

import httpx
from pydantic import ValidationError

from context_store.store import DEFAULT_DB_PATH, SecurityContextStore
from evidence_harness.harness import EvidenceHarness
from exploit_agent.agent import ExploitAgent
from hypothesis_engine.engine import HypothesisEngine
from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from shared.cost import CostService
from shared.id_generator import generate_id
from shared.kill_switch import AutomaticThresholdReason, KillSwitch, StopSource
from shared.models.action import ActionPlanResult, ActionPlanStatus, ActionSpec
from shared.models.entities import Authorization, AuthorizationLayer
from shared.models.hypothesis import Hypothesis, HypothesisProvenance, HypothesisStatus
from shared.models.kill_switch import ExecutionStatus
from shared.models.observation import NormalizedObservation
from shared.models.signal import NormalizedSignal, SignalCoverage
from shared.models.verification_package import Environment, ReviewDecision, VerificationPackage
from verdict_oracle.oracle import decide
from verdict_oracle.predicates import evaluate_predicates
from verification_package.assembler import assemble_verification_package

DEFAULT_EVIDENCE_STORAGE_DIR = ".secweave/evidence"


class CliError(Exception):
    """Raised by business-logic helpers/orchestration functions for a
    user-facing error condition. Every cmd_* function catches this at its
    boundary, prints `error: {message}` to stderr, and returns 1 — the
    single place presentation (printing, exit codes) meets business logic,
    so the logic itself stays callable/testable directly (construct
    inputs, assert on a return value or a raised CliError) without going
    through argparse or capturing stdout."""


def _open_context_store(db_path: str) -> SecurityContextStore:
    """Opens the Context Store, raising CliError with a clean message on
    failure — every cmd_* function needing a store hits this shape (a
    constructor failure is sqlite3.Error, not the RuntimeError store
    methods raise, so it needs its own handling)."""
    try:
        return SecurityContextStore(db_path=db_path)
    except sqlite3.Error as exc:
        raise CliError(f"không mở được Context Store tại '{db_path}': {exc}") from exc


_EnumT = TypeVar("_EnumT", bound=Enum)


def _parse_enum_arg(enum_cls: Type[_EnumT], raw: str, flag_name: str) -> _EnumT:
    """Parses a CLI flag's raw string into an Enum member, raising a
    uniform CliError listing every valid choice on failure — the same
    shape was repeated 4x across --environment/--decision/--source/
    --automatic-threshold-reason before being pulled out here."""
    try:
        return enum_cls(raw)
    except ValueError:
        valid = ", ".join(member.value for member in enum_cls)
        raise CliError(f"{flag_name} không hợp lệ '{raw}' — chỉ chấp nhận: {valid}")


def _print_skip_warning(message: str) -> None:
    print(f"CẢNH BÁO: {message}", file=sys.stderr)


def _load_signals(args: argparse.Namespace) -> List[NormalizedSignal]:
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
        raise CliError(f"không tìm thấy file '{args.signal}'")
    except ValueError as exc:
        raise CliError(str(exc)) from exc


def cmd_normalize(args: argparse.Namespace) -> int:
    try:
        signals = _load_signals(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
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
    """Builds an LLM client according to --llm-mode, printing the matching
    warning (a safety disclosure, not error handling — always fires on
    success). Raises CliError if construction fails in api mode (missing
    env var)."""
    if args.llm_mode == "agent":
        from hypothesis_engine.llm_client.agent_bridge_client import AgentBridgeLLMClient

        llm_client = AgentBridgeLLMClient()
        print(f"CẢNH BÁO: chế độ agent-bridge — không gọi API nào. {agent_mode_message}", file=sys.stderr)
        return llm_client

    from hypothesis_engine.llm_client.openai_compatible_client import OpenAICompatibleLLMClient

    try:
        llm_client = OpenAICompatibleLLMClient()
    except RuntimeError as exc:
        raise CliError(str(exc)) from exc
    print(
        f"CẢNH BÁO: sắp gửi {api_mode_subject} tới LLM thật (model={llm_client.model}).",
        file=sys.stderr,
    )
    return llm_client


def cmd_hypothesize(args: argparse.Namespace) -> int:
    try:
        return _run_hypothesize(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_hypothesize(args: argparse.Namespace) -> int:
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
            # Real gap found via independent review: only FileNotFoundError
            # was caught — realistic misuse like --source pointing at a
            # DIRECTORY (IsADirectoryError) or an unreadable file
            # (PermissionError) crashed with a raw traceback instead of
            # this command's otherwise-clean failure path. Both are OSError
            # subclasses, caught together here.
            raise CliError(f"không đọc được source file '{args.source}': {exc}") from exc
        except UnicodeDecodeError as exc:
            # A binary/non-UTF8 file is equally realistic --source misuse
            # (e.g. accidentally pointing at a compiled artifact) and isn't
            # an OSError, so needs its own clean handling.
            raise CliError(f"source file '{args.source}' không phải text UTF-8: {exc}") from exc

    context_store = _open_context_store(args.context_db)

    try:
        verified_context = (
            context_store.get_verified_context(args.target_id) if args.target_id else []
        )
        # SPEC §4.6 write-path diagram's dashed arrow: "unverified: chỉ tra
        # cứu, có nhãn cảnh báo" — a real, sanctioned read pathway, not a
        # future TODO. build_prompt() labels this separately from
        # verified_context so the LLM can't mistake "captured once, never
        # reviewed" for confirmed fact.
        unverified_context = (
            context_store.get_unverified_context(args.target_id) if args.target_id else []
        )
    except RuntimeError as exc:
        # Real gap found via independent review: get_verified_context() had
        # no exception handling at all — a real sqlite failure here (e.g.
        # lock contention) used to escape uncaught and dump a raw
        # traceback instead of this clean error.
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
                    context_store.record_hypothesis(result, signal)
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


def _record_for_json(record: dict) -> dict:
    """Decodes `location` from its stored JSON-string form into a nested
    object, matching the un-double-encoded shape `hypothesize --format
    json` already outputs for the same logical field.
    """
    result = dict(record)
    if result.get("location") is not None:
        result["location"] = json.loads(result["location"])
    return result


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


def _load_hypothesis_records(args: argparse.Namespace) -> List[dict]:
    context_store = _open_context_store(args.context_db)
    try:
        if args.hypothesis_id:
            record = context_store.get_hypothesis(args.hypothesis_id)
            records = [record] if record is not None else []
        else:
            # hypothesis_id only exists when status=hypothesis — a
            # NOT_VERIFIABLE record (no Hypothesis was ever created) can only
            # be looked up by signal_id, it has no hypothesis_id to query by.
            records = context_store.get_hypotheses_by_signal_id(args.signal_id)
    except RuntimeError as exc:
        raise CliError(str(exc)) from exc
    finally:
        context_store.close()

    if not records:
        key = f"hypothesis_id '{args.hypothesis_id}'" if args.hypothesis_id else f"signal_id '{args.signal_id}'"
        raise CliError(f"không tìm thấy bản ghi nào cho {key}")
    return records


def cmd_show_hypothesis(args: argparse.Namespace) -> int:
    try:
        records = _load_hypothesis_records(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        payload = [_record_for_json(r) for r in records] if args.signal_id else _record_for_json(records[0])
        print(json.dumps(payload, indent=2, ensure_ascii=False))
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


def _load_hypothesis_from_context_store(context_store: SecurityContextStore, hypothesis_id: str) -> Hypothesis:
    """Looks up a stored Hypothesis by id, raising CliError on any failure
    (not found, store error, or a schema mismatch while reconstructing
    it) — shared by `plan` and `execute` (without --plan-file), both of
    which start from a stored hypothesis_id the same way. Closes
    `context_store` once the lookup itself is done, before the
    (network-free) reconstruction step.
    """
    try:
        record = context_store.get_hypothesis(hypothesis_id)
    except RuntimeError as exc:
        raise CliError(str(exc)) from exc
    finally:
        context_store.close()

    if record is None:
        raise CliError(
            f"không tìm thấy hypothesis_id '{hypothesis_id}' (chỉ tra được bản ghi "
            "status=hypothesis, không tra được not_verifiable)"
        )

    try:
        return _load_stored_hypothesis(record)
    except ValueError as exc:
        raise CliError(str(exc)) from exc


def _build_local_test_authorization(args: argparse.Namespace) -> Authorization:
    """Local-test-only Authorization stub built from --allowed-action —
    never a real Gate 2/3 record. Caller prints its own warning first
    (what's actually risky differs between `plan`, a dry-run, and
    `execute`, which sends real requests)."""
    return Authorization(
        id=generate_id("auth"),
        layer=AuthorizationLayer.TARGET_AUTHORIZATION,
        approved_by="cli-local-test",
        approved_at=datetime.now(timezone.utc),
        allowed_actions=args.allowed_action or [],
    )


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        return _run_plan(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_plan(args: argparse.Namespace) -> int:
    context_store = _open_context_store(args.context_db)
    hypothesis = _load_hypothesis_from_context_store(context_store, args.hypothesis_id)

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


def _load_frozen_plan(args: argparse.Namespace) -> ActionPlanResult:
    """Loads a plan PREVIOUSLY produced and reviewed by `secweave plan
    --format json > file`, instead of asking the LLM to plan again — so
    the plan a human reviewed is guaranteed to be the one that executes
    (SPEC §5.1: no LLM call between "Plan & dry-run" and "Execute").
    Deliberately a plain file, not stored in Context Store (SPEC §4.6
    scopes that store to knowledge accumulated ACROSS runs, not an
    in-flight execution artifact — same operator-supplied, not-persisted
    handling as Authorization/the allowlist).

    Raises CliError on any failure. `args.hypothesis_id` is cross-checked
    against BOTH the file's top-level hypothesis_id AND the embedded
    ActionPlan.hypothesis_id, so the two can't silently disagree — this is
    self-consistency of what the file claims, not proof against Context
    Store ground truth (the whole point of --plan-file is to skip that
    lookup).
    """
    try:
        plan_data = json.loads(Path(args.plan_file).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CliError(f"không tìm thấy plan file '{args.plan_file}'")
    except OSError as exc:
        raise CliError(f"không đọc được plan file '{args.plan_file}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CliError(f"plan file '{args.plan_file}' không phải JSON hợp lệ: {exc}") from exc

    if not isinstance(plan_data, dict) or plan_data.get("hypothesis_id") != args.hypothesis_id:
        raise CliError(
            f"plan file '{args.plan_file}' được lập cho hypothesis_id "
            f"'{plan_data.get('hypothesis_id') if isinstance(plan_data, dict) else '?'}', không khớp "
            f"--hypothesis-id đã truyền ('{args.hypothesis_id}') — có thể đang dùng nhầm file plan."
        )

    plan_result_data = plan_data.get("plan_result")
    if not isinstance(plan_result_data, dict):
        raise CliError(f"plan file '{args.plan_file}' thiếu field 'plan_result'.")

    try:
        plan_result = ActionPlanResult(**plan_result_data)
    except ValidationError as exc:
        raise CliError(
            f"plan file '{args.plan_file}' có 'plan_result' không đúng schema ActionPlanResult: {exc}"
        ) from exc

    if plan_result.plan is not None and plan_result.plan.hypothesis_id != args.hypothesis_id:
        raise CliError(
            f"plan file '{args.plan_file}': plan_result.plan.hypothesis_id "
            f"('{plan_result.plan.hypothesis_id}') không khớp --hypothesis-id đã truyền "
            f"('{args.hypothesis_id}') — dù hypothesis_id ở cấp ngoài của file khớp, ActionPlan bên "
            "trong lại thuộc về 1 hypothesis khác. Có thể file đã bị sửa tay hoặc ghép nhầm."
        )

    print(f"-> Dùng lại plan ĐÃ ĐÓNG BĂNG từ '{args.plan_file}' (không gọi LLM lại).")
    return plan_result


def cmd_execute(args: argparse.Namespace) -> int:
    """Thực thi THẬT các action đã approve của 1 plan — nối KillSwitch/
    CostService/EvidenceHarness vào CLI, thứ 3 thành phần này trước đó chỉ
    chạy được qua script thủ công (.secweave/manual_test/*.py), chưa từng
    có entrypoint CLI/API thật nào (real gap tìm được qua review toàn dự
    án). Mỗi action được capture với đúng `action.role` mà Exploit Agent đã
    gắn cho nó khi lập plan (ActionSpec.role, mặc định main nếu plan không
    tự gắn role nào khác) — không còn hardcode role=main cho mọi action như
    trước (2026-08-19: đóng phần "role tagging" của gap 3-role).

    SCOPE THẬT còn lại: mọi action vẫn dùng CHUNG 1 identity (`--identity`)
    dù role có khác nhau — 1 kịch bản 3-role đúng nghĩa (positive_control
    đọc bằng chính danh tính chủ sở hữu, denied_control đọc bằng danh tính
    khác) cần nhiều identity/session thật trong CÙNG 1 lượt chạy, và cần tự
    seed blind marker (EvidenceHarness.generate_marker(), chưa wire vào
    lệnh này) để "main" có thể SATISFIED thay vì luôn INSUFFICIENT_DATA —
    cả 2 phần đó vẫn cần script tự viết như
    .secweave/manual_test/identity_scenario_example.py. decide() vẫn được
    gọi ở cuối để verdict thật ra đúng INCONCLUSIVE khi thiếu nhóm predicate
    nào đó, thay vì giả vờ có thể kết luận CONFIRMED/NOT_REPRODUCED từ 1
    identity/role.

    `--plan-file`: dùng lại đúng plan đã `secweave plan` duyệt trước đó
    thay vì gọi LLM lập plan MỚI (xem _load_frozen_plan's docstring cho lý
    do). Không truyền cờ này vẫn hoạt động như trước — tiện cho test nhanh
    1 bước — nhưng KHÔNG đảm bảo plan thực thi giống plan đã xem qua
    `secweave plan` trước đó, vì LLM không xác định.
    """
    try:
        return _run_execute(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_execute(args: argparse.Namespace) -> int:
    if args.plan_file:
        plan_result = _load_frozen_plan(args)
        # review_plan()/check_plan()/check_cost() are pure Policy/Cost logic
        # (shared/policy.py, shared/cost.py) — none of them ever touch
        # self._llm_client, so no real LLM client is needed just to call
        # them. Avoids requiring LLM_API_KEY (or a Claude Code session, in
        # --llm-mode agent) at all for a run that's replaying an
        # already-frozen plan and never calls the LLM again.
        agent = ExploitAgent(llm_client=None)
    else:
        print(
            "CẢNH BÁO: không có --plan-file — plan sẽ được LLM lập MỚI ngay bây giờ, có thể KHÁC "
            "plan đã xem qua `secweave plan` trước đó (LLM không xác định). Dùng --plan-file để đảm "
            "bảo thực thi ĐÚNG plan đã duyệt.",
            file=sys.stderr,
        )
        context_store = _open_context_store(args.context_db)
        hypothesis = _load_hypothesis_from_context_store(context_store, args.hypothesis_id)

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

    if plan_result.status == ActionPlanStatus.NOT_PLANNABLE:
        print(f"NOT_PLANNABLE — {plan_result.reason}")
        return 0

    print(
        "CẢNH BÁO: authorization dùng để check dưới đây CHỈ dựng tạm để test cục bộ từ "
        "--allowed-action — KHÔNG phải Gate 2/3 thật đã duyệt. Lệnh này SẼ GỬI REQUEST THẬT tới "
        "các host trong allowlist — chỉ chạy khi bạn thực sự được phép làm điều đó trên target đó.",
        file=sys.stderr,
    )
    authorization = _build_local_test_authorization(args)
    review = agent.review_plan(plan_result.plan, authorization, cap=args.cap)
    if not review.approved:
        print("-> Kết quả tổng: BLOCKED — không action nào được thực thi.")
        for check in review.plan_check.checks:
            verdict = "PASS" if check.decision.allowed else "FAIL"
            print(f"  [{verdict}] {check.action.method} {check.action.target} — {check.decision.reason}")
        if not review.cost_check.allowed:
            print(f"  Cost: {review.cost_check.reason}")
        return 1

    execution_id = args.execution_id or generate_id("exec")
    kill_switch = KillSwitch(execution_id=execution_id, storage_dir=args.storage_dir)

    # Real gap found via independent review: kill_switch.start() used to be
    # called unconditionally, which crashes uncaught with a raw ValueError
    # the moment an operator reuses an --execution-id whose PRIOR execute
    # invocation ever succeeded even once (status would already be RUNNING,
    # since nothing yet drives it to COMPLETED — see
    # shared/models/kill_switch.py's ExecutionStatus docstring) or was
    # STOPPED. Reusing an execution_id across multiple `execute` invocations
    # is exactly how CostService's own cap is meant to accumulate real
    # meaning (shared/cost.py: "a caller reusing one execution_id across
    # more than one plan") — so this must be handled, not crash.
    if kill_switch.status == ExecutionStatus.PREPARED:
        kill_switch.start()
    elif kill_switch.status == ExecutionStatus.STOPPED:
        raise CliError(
            f"execution '{execution_id}' đã STOPPED trước đó — không tự động tiếp tục "
            "(SPEC §6.4 control #10: không tiếp tục sau stop-work trigger nếu chưa được cho phép "
            f"chạy lại). Chạy `secweave resume --execution-id {execution_id} --storage-dir "
            f"{args.storage_dir} --authorization-reference '...'` trước, rồi execute lại."
        )
    # else: RUNNING — a prior `execute` for this execution_id already
    # started it; continue accumulating against the same KillSwitch/
    # CostService state rather than re-starting.

    cost_service = CostService(execution_id=execution_id, storage_dir=args.storage_dir, cap=args.cap)
    # Separate instance from the one opened above (in the non---plan-file
    # branch, to fetch a stored hypothesis) — that one is already closed by
    # this point. This one stays open for the whole execute loop, closed in
    # the `finally:` below alongside harness.close(), so every capture()
    # can write its SPEC §4.6 unverified observation as it happens.
    execution_context_store = _open_context_store(args.context_db)
    harness = EvidenceHarness(
        execution_id=execution_id,
        target_id=args.target_id,
        target_revision_id=args.target_revision_id,
        storage_dir=args.storage_dir,
        kill_switch=kill_switch,
        cost_service=cost_service,
        context_store=execution_context_store,
    )
    harness_storage_dir = Path(args.storage_dir) / execution_id  # matches EvidenceHarness's own layout

    # Persisted so a later, separate `secweave assemble-package` invocation
    # can reconstruct VerificationPackage's `actions` input (SPEC §7 field
    # #9) without needing the original --plan-file to still be lying
    # around. MERGED with whatever's already on disk (by action_id), not
    # overwritten — real gap found via independent review: reusing one
    # execution_id across multiple `execute` calls with DIFFERENT plans is
    # an explicitly supported pattern elsewhere in this codebase (kill-
    # switch RUNNING-continuation branch, CostService cap accumulation —
    # see this function's own comment above on kill_switch.status), and
    # observations.jsonl already accumulates across such calls. Overwriting
    # actions.json with only THIS invocation's actions permanently and
    # unrecoverably broke `assemble-package` for exactly that pattern — an
    # earlier call's ActionSpec, still referenced by an earlier
    # observation's action_ref, would vanish from the file entirely.
    actions_path = harness_storage_dir / "actions.json"
    existing_actions_raw = json.loads(actions_path.read_text(encoding="utf-8")) if actions_path.exists() else []
    existing_action_ids = {item["action_id"] for item in existing_actions_raw}
    merged_actions_raw = existing_actions_raw + [
        action.model_dump(mode="json")
        for action in plan_result.plan.actions
        if action.action_id not in existing_action_ids
    ]
    actions_path.write_text(json.dumps(merged_actions_raw, indent=2), encoding="utf-8")

    print(f"-> execution_id: {execution_id}")
    print(
        f"-> Đang thực thi {len(plan_result.plan.actions)} action đã approve (identity="
        f"'{args.identity}' cho tất cả — mỗi action tự mang role riêng do Exploit Agent gắn, "
        "mặc định main nếu plan không tự gắn role nào khác)..."
    )

    # Parameter names whose VALUES must never be written to the raw evidence
    # transcript — see EvidenceHarness.capture()'s docstring.
    sensitive_body_keys = set(args.sensitive_param or [])
    observations = []
    stopped_reason = None
    try:
        for check in review.plan_check.checks:
            try:
                observation = harness.capture(
                    check.action,
                    role=check.action.role,
                    identity=args.identity,
                    sensitive_body_keys=sensitive_body_keys,
                )
            except RuntimeError as exc:
                # Real gap found via independent review: catching only
                # (ExecutionStoppedError, CostCapExceededError) missed a
                # bare RuntimeError from CostService.record_action()'s own
                # write-failure path (shared/cost.py) or KillSwitch's
                # audit-log write failure (shared/kill_switch.py, now
                # wrapped there too) — both ARE RuntimeError subclasses
                # already, so catching the base class covers all 3
                # uniformly instead of missing the 2 that aren't explicitly
                # named here.
                stopped_reason = str(exc)
                print(f"   DỪNG GIỮA CHỪNG: {exc}", file=sys.stderr)
                break
            observations.append(observation)
            # Real gap found via independent review: capture() returns a
            # structured NormalizedObservation, but cmd_execute previously
            # only ever used it in-memory (for decide(), below) and never
            # persisted it — only the raw request/response transcript
            # landed on disk (evidence_harness/harness.py), in a shape
            # that's missing execution_id/target_id/target_revision_id/
            # channel/raw_evidence_hash/access_result. That left NO path
            # (via CLI or by reading files back) to reconstruct the
            # observations needed to assemble a VerificationPackage after
            # the fact — only hand re-deriving every field from the raw
            # transcript, error-prone and undocumented. Appended one JSON
            # object per line (not a single JSON array rewritten each time)
            # so a crash/kill mid-loop loses at most the one in-flight
            # write, matching the same append-only philosophy as the
            # kill-switch/cost audit logs, and so multiple `execute`
            # invocations reusing one execution_id accumulate here too.
            observations_log_path = harness_storage_dir / "observations.jsonl"
            with open(observations_log_path, "a", encoding="utf-8") as f:
                f.write(observation.model_dump_json() + "\n")
            print(
                f"   [{observation.access_result.value}] {check.action.method} {check.action.target} "
                f"(HTTP {observation.status_code})"
            )
    finally:
        harness.close()
        execution_context_store.close()

    print(f"-> Kill-switch status cuối: {kill_switch.status.value}")
    print(f"-> Cost: {cost_service.executed_action_count}/{cost_service.cap}")

    # Real gap found via independent review: this was only ever a local
    # variable used for THIS invocation's own decide() call, never
    # persisted — a later, separate `secweave assemble-package` invocation
    # had no way to know whether the execution it's assembling a package
    # for actually COMPLETED or was STOPPED partway (a distinction
    # decide()/assemble_verdict() treat as safety-critical: SPEC §3.4 only
    # allows CONFIRMED/NOT_REPRODUCED when COMPLETED). Persisted
    # unconditionally (not just when this invocation captured new
    # observations) so it always reflects this invocation's real outcome,
    # even across multiple `execute` calls reusing one execution_id.
    execution_status = ExecutionStatus.STOPPED if stopped_reason else ExecutionStatus.COMPLETED
    (harness_storage_dir / "execution_status.json").write_text(
        json.dumps({"execution_status": execution_status.value}), encoding="utf-8"
    )

    if observations:
        result = decide(observations, execution_status=execution_status)
        print(f"-> Verdict: {result.verdict.value}")
        print(f"   {result.reason}")

    return 1 if stopped_reason else 0


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
        observations = [
            NormalizedObservation(**json.loads(line))
            for line in observations_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        actions = [ActionSpec(**item) for item in json.loads(actions_path.read_text(encoding="utf-8"))]
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
    trong file — review độc lập tìm ra: 1 file JSON bị sửa tay (fabricate
    `verdict`+`predicate_results` khớp nhau về logic nội bộ, nhưng không
    khớp với `normalized_observations` thật) vẫn qua được mọi validator
    hiện có, vì các validator chỉ kiểm NỘI BỘ package tự nhất quán, không
    đối chiếu lại với observation thật. Sửa bằng cách tính lại
    `evaluate_predicates()` trên đúng `normalized_observations` trong file
    rồi so với `predicate_results` đã khai — lệch là từ chối, không hỏi gì
    thêm.
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
    except json.JSONDecodeError as exc:
        raise CliError(f"'{package_path}' không phải JSON hợp lệ: {exc}") from exc

    decision = _parse_enum_arg(ReviewDecision, args.decision, "--decision")

    if args.retest_reference and decision != ReviewDecision.RETEST:
        # Real gap found via independent review: --retest-reference could be
        # set together with ANY decision (vd release), tạo ra 1 package vừa
        # is_release_ready=True vừa mang retest_reference — mâu thuẫn với
        # đúng ý nghĩa field #19 ("absent until retests have run").
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
        # Real bypass found via independent review: without this check, a
        # hand-edited package file with a fabricated verdict=confirmed +
        # matching (but fake) predicate_results — while normalized_
        # observations was left untouched, still showing no real satisfying
        # evidence — passed every existing validator (they only check
        # INTERNAL consistency, e.g. "CONFIRMED requires all 3 groups
        # satisfied," never that predicate_results actually reflects the
        # observations it claims to summarize) and came out the other end
        # with a legitimate-looking, decision=release human_review_record
        # attached. Recomputing from the package's OWN normalized_
        # observations and refusing on any mismatch closes this — a real
        # assemble-package run always produces a package where these agree,
        # so this never fires for output that wasn't hand-tampered with.
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
        # Real gap found via independent review: overwriting silently left
        # zero trace that a PRIOR reviewer's decision (e.g. a reject) ever
        # existed. Not blocked outright (a legitimate re-review after a
        # rejected package gets fixed and reassembled is a real workflow),
        # but surfaced loudly so an operator watching the terminal/log sees
        # exactly what's being replaced.
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
        # Rebuilding the WHOLE object (not a partial model_copy(update=...),
        # which does not re-run validators) so every validator — including
        # HumanReviewRecord's own decision=release/checked_raw_artifact
        # check and VerificationPackage's predicate-completeness checks —
        # runs again against the fully updated data, not just the new field
        # in isolation.
        package = VerificationPackage(**package_data)
    except ValidationError as exc:
        raise CliError(f"không gắn được human_review_record vào package: {exc}") from exc

    if decision == ReviewDecision.RELEASE:
        # SPEC §4.6 write path, step 2: "Human Review -- phát hành package
        # -> chuyển verified --> Context Store." Only reachable here because
        # decision=release + checked_raw_artifact=true was already enforced
        # above (HumanReviewRecord's own validator) — promotion never runs
        # for a reject/retest decision, matching the diagram's own arrow
        # (only a released package promotes anything).
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


def cmd_mark_stale(args: argparse.Namespace) -> int:
    """SPEC §4.6's staleness principle: khi 1 target/revision có thay đổi
    mà không xác định được chính xác phạm vi ảnh hưởng, đánh dấu CŨ RỘNG
    HƠN toàn bộ context đã lưu cho target đó (cả verified lẫn unverified)
    thay vì giữ lại dữ kiện có khả năng sai — "thà phân tích lại thừa còn
    hơn xây giả thuyết trên nền cũ". Đây là quyết định của con người/
    operator (biết target đã đổi revision), không phải thứ hệ thống tự
    phát hiện được — không có cách nào để code tự động biết "phạm vi ảnh
    hưởng không xác định được" nghĩa là gì cho 1 target cụ thể.
    """
    try:
        context_store = _open_context_store(args.context_db)
        try:
            marked = context_store.mark_stale(args.target_id, args.reason)
        except RuntimeError as exc:
            raise CliError(str(exc)) from exc
        finally:
            context_store.close()
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"-> Đã đánh dấu cũ {marked} bản ghi (verified + unverified) cho target_id '{args.target_id}'.")
    return 0


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
    source = _parse_enum_arg(StopSource, args.source, "--source")

    automatic_threshold_reason = None
    if args.automatic_threshold_reason:
        automatic_threshold_reason = _parse_enum_arg(
            AutomaticThresholdReason, args.automatic_threshold_reason, "--automatic-threshold-reason"
        )

    kill_switch = KillSwitch(execution_id=args.execution_id, storage_dir=args.storage_dir)
    # Captured BEFORE stop() (which immediately appends its own event) —
    # real gap found via independent review: a mistyped/never-started
    # --execution-id silently succeeds (PREPARED is a valid, intentional
    # state to stop() from — "abort before start()" — so this can't just
    # be rejected outright), printing output textually IDENTICAL to a real
    # successful stop. An operator relying on this command for an
    # unambiguous panic-stop confirmation deserves an explicit signal that
    # nothing was actually running under this id.
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
    kill_switch = KillSwitch(execution_id=args.execution_id, storage_dir=args.storage_dir)
    try:
        kill_switch.resume(actor=args.actor, authorization_reference=args.authorization_reference)
    except ValueError as exc:
        raise CliError(str(exc)) from exc

    print(f"-> execution '{args.execution_id}': resume")
    print(f"   status hiện tại: {kill_switch.status.value}")
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


def _add_format_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", default="table", choices=["table", "json"])


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
    _add_format_arg(normalize_parser)
    normalize_parser.set_defaults(func=cmd_normalize)

    hypothesize_parser = subparsers.add_parser(
        "hypothesize",
        help="Sinh Hypothesis từ 1 report thô — dùng LLM API thật, hoặc bắc cầu qua agent (--llm-mode)",
    )
    _add_report_args(hypothesize_parser)
    hypothesize_parser.add_argument("--source", help="Đường dẫn file source code liên quan (tuỳ chọn)")
    hypothesize_parser.add_argument("--target-id", help="target_id để tra verified context (tuỳ chọn)")
    _add_llm_mode_arg(hypothesize_parser)
    _add_format_arg(hypothesize_parser)
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
        help='1 entry allowlist, dạng "METHOD https://host/path/{param} [params:key1,key2=regex]" — có '
        "thể lặp lại flag này nhiều lần để cấp nhiều entry. Không truyền = allowlist rỗng = mọi action "
        "đều bị chặn. Phần 'params:...' tuỳ chọn: liệt kê tên field được phép xuất hiện trong "
        "ActionSpec.parameters (query string hoặc JSON body) của action đó — không ghi thì mặc định "
        "action PHẢI có parameters rỗng, không phải 'cho phép tất cả'. Mỗi key có thể kèm "
        "'=regex' (vd 'userId=^[0-9]+$') để bắt buộc GIÁ TRỊ của key đó khớp pattern, không chỉ tên "
        "key — key không có '=regex' thì vẫn nhận mọi giá trị như trước.",
    )
    plan_parser.add_argument(
        "--cap", type=int, default=10, help="Cap số hành động dự kiến tối đa trong plan (mặc định: %(default)s)"
    )
    _add_llm_mode_arg(plan_parser)
    _add_format_arg(plan_parser)
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
    _add_format_arg(show_hypothesis_parser)
    _add_context_db_arg(show_hypothesis_parser)
    show_hypothesis_parser.set_defaults(func=cmd_show_hypothesis)

    execute_parser = subparsers.add_parser(
        "execute",
        help="Thực thi THẬT các action đã approve của 1 plan (nối KillSwitch/CostService/"
        "EvidenceHarness) — SẼ GỬI REQUEST THẬT, chỉ chạy khi thực sự được phép trên target đó",
    )
    execute_parser.add_argument(
        "--hypothesis-id", required=True, help="hypothesis_id đã lưu trong Context Store (từ `hypothesize`)"
    )
    execute_parser.add_argument(
        "--plan-file",
        help="Dùng lại ĐÚNG plan đã `secweave plan --format json > file` lập và duyệt trước đó, thay "
        "vì gọi LLM lập plan MỚI (LLM không xác định — 2 lần gọi có thể ra 2 plan khác nhau cho cùng "
        "1 hypothesis). Không truyền cờ này thì vẫn lập plan mới như trước, tiện cho test nhanh 1 "
        "bước nhưng KHÔNG đảm bảo thực thi đúng plan đã xem qua `secweave plan`. Khớp SPEC §5.1: "
        "'Plan & dry-run' phải feed thẳng plan sang 'Execute', không lập lại giữa chừng.",
    )
    execute_parser.add_argument(
        "--allowed-action",
        action="append",
        help='Giống hệt `plan --allowed-action` — 1 entry allowlist, dạng "METHOD https://host/path/'
        '{param} [params:key1,key2=regex]", lặp lại flag để cấp nhiều entry.',
    )
    execute_parser.add_argument(
        "--cap",
        type=int,
        default=10,
        help="Cap số hành động — dùng CHUNG cho cả cost-check lúc lập plan lẫn CostService lúc thực "
        "thi thật (mặc định: %(default)s)",
    )
    execute_parser.add_argument("--target-id", required=True, help="target_id ghi vào evidence")
    execute_parser.add_argument("--target-revision-id", required=True, help="target_revision_id ghi vào evidence")
    execute_parser.add_argument(
        "--execution-id", help="Định danh execution (mặc định: tự sinh mới mỗi lần chạy)"
    )
    execute_parser.add_argument(
        "--storage-dir",
        default=DEFAULT_EVIDENCE_STORAGE_DIR,
        help="Thư mục lưu evidence + kill-switch/cost audit log (mặc định: %(default)s)",
    )
    execute_parser.add_argument(
        "--identity", default="anonymous", help="Identity dùng để gửi mọi action (mặc định: %(default)s)"
    )
    execute_parser.add_argument(
        "--sensitive-param",
        action="append",
        help="Tên field trong ActionSpec.parameters (hoặc query string cùng tên trong target) mà GIÁ "
        "TRỊ không được ghi ra đĩa trong transcript bằng chứng — lặp lại flag để khai nhiều field "
        "(vd --sensitive-param password --sensitive-param api_key). Chỉ ảnh hưởng bản ghi lưu lại, "
        "không ảnh hưởng request thật đã gửi. Không truyền = không field nào được coi là nhạy cảm "
        "ngoài header Authorization/Cookie/Set-Cookie (luôn redact sẵn).",
    )
    _add_llm_mode_arg(execute_parser)
    _add_context_db_arg(execute_parser)
    execute_parser.set_defaults(func=cmd_execute)

    kill_parser = subparsers.add_parser(
        "kill",
        help="Dừng 1 execution đang chạy — gọi được từ process/terminal khác với process đang chạy "
        "`execute` (SPEC §6.3: 5 nguồn người + 1 ngưỡng tự động)",
    )
    kill_parser.add_argument("--execution-id", required=True, help="execution_id cần dừng")
    kill_parser.add_argument(
        "--storage-dir",
        default=DEFAULT_EVIDENCE_STORAGE_DIR,
        help="Phải TRÙNG --storage-dir đã dùng khi `execute` execution này (mặc định: %(default)s)",
    )
    kill_parser.add_argument(
        "--source",
        required=True,
        choices=[s.value for s in StopSource],
        help="Nguồn dừng (SPEC §6.3)",
    )
    kill_parser.add_argument("--reason", required=True, help="Lý do dừng (ghi vào audit log)")
    kill_parser.add_argument("--actor", help="Người/hệ thống thực hiện lệnh dừng (tuỳ chọn)")
    kill_parser.add_argument(
        "--automatic-threshold-reason",
        choices=[r.value for r in AutomaticThresholdReason],
        help="BẮT BUỘC nếu --source=automatic_threshold — 1 trong 5 điều kiện SPEC §6.3",
    )
    kill_parser.set_defaults(func=cmd_kill)

    resume_parser = subparsers.add_parser(
        "resume",
        help="Đưa 1 execution đã STOPPED quay lại RUNNING — đường DUY NHẤT (SPEC §6.4 control #10), "
        "cần thiết để `execute` lại sau khi bị `kill`",
    )
    resume_parser.add_argument("--execution-id", required=True, help="execution_id cần resume")
    resume_parser.add_argument(
        "--storage-dir",
        default=DEFAULT_EVIDENCE_STORAGE_DIR,
        help="Phải TRÙNG --storage-dir đã dùng khi `execute`/`kill` execution này (mặc định: %(default)s)",
    )
    resume_parser.add_argument("--actor", help="Người/hệ thống thực hiện lệnh resume (tuỳ chọn)")
    resume_parser.add_argument(
        "--authorization-reference",
        required=True,
        help="Mô tả phê duyệt thật đã cho phép resume (vd 'owner re-approved qua email lúc ...') — "
        "bắt buộc ở mức CLI để không resume() mà không ghi lại lý do thật, dù bản thân "
        "KillSwitch.resume() cho phép để trống",
    )
    resume_parser.set_defaults(func=cmd_resume)

    assemble_package_parser = subparsers.add_parser(
        "assemble-package",
        help="Lắp Verification Package (SPEC §7) từ artifact thật của 1 lượt `execute` đã chạy — đọc "
        "lại observations.jsonl/actions.json/execution_status.json, không cần --plan-file gốc",
    )
    assemble_package_parser.add_argument("--execution-id", required=True, help="execution_id đã `execute`")
    assemble_package_parser.add_argument(
        "--storage-dir",
        default=DEFAULT_EVIDENCE_STORAGE_DIR,
        help="Phải TRÙNG --storage-dir đã dùng khi `execute` execution này (mặc định: %(default)s)",
    )
    assemble_package_parser.add_argument("--target-id", required=True, help="target_id — trường #2 SPEC §7")
    assemble_package_parser.add_argument(
        "--target-revision-id", required=True, help="Dùng làm revision — trường #4 SPEC §7"
    )
    assemble_package_parser.add_argument(
        "--environment",
        required=True,
        choices=[e.value for e in Environment],
        help="Trường #3 SPEC §7 — target không bao giờ được là production (NX-GO-02)",
    )
    assemble_package_parser.add_argument(
        "--authorization-reference",
        required=True,
        help="Mô tả phê duyệt thật đã cho phép lượt chạy này (trường #5 SPEC §7) — bắt buộc, không có "
        "giá trị mặc định, vì đây là phán đoán của con người không tự sinh được",
    )
    assemble_package_parser.add_argument(
        "--scenario", required=True, help="Mô tả kịch bản đã kiểm chứng (trường #6 SPEC §7) — bắt buộc"
    )
    assemble_package_parser.add_argument(
        "--limitations",
        required=True,
        help="Giới hạn thật của lượt chạy này (trường #17 SPEC §7, 'nên đọc đầu tiên') — bắt buộc",
    )
    assemble_package_parser.add_argument(
        "--next-action", required=True, help="Bước tiếp theo đề xuất (trường #18 SPEC §7) — bắt buộc"
    )
    _add_format_arg(assemble_package_parser)
    assemble_package_parser.set_defaults(func=cmd_assemble_package)

    review_package_parser = subparsers.add_parser(
        "review-package",
        help="Gate 4 — Human Review Loop tối thiểu (SPEC §4.5): gắn quyết định review của con người "
        "vào 1 Verification Package đã lắp qua `assemble-package`",
    )
    review_package_parser.add_argument(
        "--package-file", required=True, help="File JSON của package đã lắp (`assemble-package --format json`)"
    )
    review_package_parser.add_argument("--reviewer", required=True, help="Tên/định danh người review")
    review_package_parser.add_argument(
        "--decision", required=True, choices=[d.value for d in ReviewDecision], help="Quyết định của người review"
    )
    review_package_parser.add_argument(
        "--reason", required=True, help="Lý do cho quyết định — bắt buộc kể cả khi release"
    )
    review_package_parser.add_argument(
        "--checked-raw-artifact",
        action="store_true",
        help="Xác nhận ĐÃ tự tay đối chiếu ít nhất 1 raw evidence reference (in ra ở stderr) với "
        "normalized observation tương ứng (SPEC §4.5) — decision=release bắt buộc phải có cờ này",
    )
    review_package_parser.add_argument(
        "--retest-reference", help="Tham chiếu tới lượt retest (nếu decision=retest) — tuỳ chọn"
    )
    _add_format_arg(review_package_parser)
    _add_context_db_arg(review_package_parser)
    review_package_parser.set_defaults(func=cmd_review_package)

    mark_stale_parser = subparsers.add_parser(
        "mark-stale",
        help="SPEC §4.6 — đánh dấu cũ toàn bộ context đã lưu (verified + unverified) cho 1 target_id, "
        "vd sau khi biết revision đã đổi nhưng chưa xác định được phạm vi ảnh hưởng chính xác",
    )
    mark_stale_parser.add_argument("--target-id", required=True, help="target_id cần đánh dấu cũ")
    mark_stale_parser.add_argument(
        "--reason", required=True, help="Lý do đánh dấu cũ (SPEC §4.6: 'lý do một mẩu ngữ cảnh bị đánh dấu là cũ')"
    )
    _add_context_db_arg(mark_stale_parser)
    mark_stale_parser.set_defaults(func=cmd_mark_stale)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    # Only auto-load .env when running the CLI for real (python cli.py ...),
    # NOT when cli.main() is called directly from a test — otherwise a real
    # .env file sitting on the dev machine would silently break a test that's
    # trying to simulate "missing env var".
    from dotenv import load_dotenv

    load_dotenv()
    raise SystemExit(main())
