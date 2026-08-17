import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

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
from shared.models.action import ActionPlanResult, ActionPlanStatus
from shared.models.entities import Authorization, AuthorizationLayer
from shared.models.hypothesis import Hypothesis, HypothesisProvenance, HypothesisStatus
from shared.models.kill_switch import ExecutionStatus
from shared.models.observation import ObservationRole
from shared.models.signal import NormalizedSignal, SignalCoverage
from verdict_oracle.oracle import decide

DEFAULT_EVIDENCE_STORAGE_DIR = ".secweave/evidence"


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
    """Builds an LLM client according to --llm-mode, printing the matching
    warning. Returns None (error already printed to stderr) if construction
    fails in api mode (missing env var)."""
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
            # encoding="utf-8" explicit — real gap found by a 2nd
            # independent review pass verifying this fix: without it,
            # read_text() defaults to locale.getpreferredencoding(False),
            # not UTF-8, so on a non-UTF-8-locale environment (e.g. a
            # minimal container with no locale configured — a realistic
            # deployment target given this project ingests CI/CD-produced
            # reports) this could either wrongly reject a genuinely valid
            # UTF-8 file, or silently decode non-UTF-8 bytes under some
            # other codec that never raises, feeding corrupted content into
            # the LLM prompt with the UnicodeDecodeError handler below
            # never firing at all.
            source_snippet = Path(args.source).read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"error: không tìm thấy source file '{args.source}'", file=sys.stderr)
            return 1
        except OSError as exc:
            # Real gap found via independent review: only FileNotFoundError
            # was caught — realistic misuse like --source pointing at a
            # DIRECTORY (IsADirectoryError) or an unreadable file
            # (PermissionError) crashed with a raw traceback instead of
            # this command's otherwise-clean failure path. Both are OSError
            # subclasses, caught together here.
            print(f"error: không đọc được source file '{args.source}': {exc}", file=sys.stderr)
            return 1
        except UnicodeDecodeError as exc:
            # A binary/non-UTF8 file is equally realistic --source misuse
            # (e.g. accidentally pointing at a compiled artifact) and isn't
            # an OSError, so needs its own clean handling.
            print(f"error: source file '{args.source}' không phải text UTF-8: {exc}", file=sys.stderr)
            return 1

    try:
        context_store = SecurityContextStore(db_path=args.context_db)
    except sqlite3.Error as exc:
        print(f"error: không mở được Context Store tại '{args.context_db}': {exc}", file=sys.stderr)
        return 1

    try:
        verified_context = (
            context_store.get_verified_context(args.target_id) if args.target_id else []
        )
    except RuntimeError as exc:
        # Real gap found via independent review: get_verified_context() had
        # no exception handling at all — a real sqlite failure here (e.g.
        # lock contention) used to escape uncaught and dump a raw
        # traceback instead of this clean error.
        print(f"error: {exc}", file=sys.stderr)
        context_store.close()
        return 1

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
        if llm_client is None:
            return 1

        engine = HypothesisEngine(llm_client)

        if args.llm_mode == "agent":
            # Merge all signals into exactly 1 question-answer round instead
            # of repeating "write prompt -> wait for Enter" for each signal
            # individually — build all the prompts first, call
            # generate_many() once, then parse each response.
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
            # Record each hypothesis IMMEDIATELY after it's generated (not
            # collected into a list and written at the end) — if a signal in
            # the middle fails (network loss, quota exhausted), the
            # hypotheses already paid for/generated before it are still kept,
            # not thrown away in an all-or-nothing fashion.
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


def _record_for_json(record: dict) -> dict:
    """Returns a copy of a Context Store row with `location` decoded from
    its stored JSON-string form into a real nested object — matching the
    shape `hypothesize --format json` already outputs (straight from the
    in-memory pydantic model, never double-JSON-encoded). Real gap found
    via independent review: without this, show-hypothesis's JSON output
    ran `location` through json.dumps() a SECOND time (it's already a JSON
    string in the DB — see context_store/store.py's schema), producing a
    doubly-escaped string instead of a nested object for the exact same
    logical field — a script consuming both commands' JSON the same way
    would break on one of them.
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
            # hypothesis_id only exists when status=hypothesis — a
            # NOT_VERIFIABLE record (no Hypothesis was ever created) can only
            # be looked up by signal_id, it has no hypothesis_id to query by.
            records = context_store.get_hypotheses_by_signal_id(args.signal_id)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        context_store.close()

    if not records:
        key = f"hypothesis_id '{args.hypothesis_id}'" if args.hypothesis_id else f"signal_id '{args.signal_id}'"
        print(f"error: không tìm thấy bản ghi nào cho {key}", file=sys.stderr)
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


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        context_store = SecurityContextStore(db_path=args.context_db)
    except sqlite3.Error as exc:
        print(f"error: không mở được Context Store tại '{args.context_db}': {exc}", file=sys.stderr)
        return 1

    try:
        record = context_store.get_hypothesis(args.hypothesis_id)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
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


def _load_frozen_plan(args: argparse.Namespace) -> Optional[ActionPlanResult]:
    """Loads a plan PREVIOUSLY produced and reviewed by `secweave plan
    --format json > file`, instead of asking the LLM to plan again. Real
    gap found via manual end-to-end testing against a live target (not
    caught by the earlier independent review, which never tested "run
    `plan` then `execute` for the SAME hypothesis"): cmd_execute used to
    ALWAYS call agent.plan() itself, a fresh, non-deterministic LLM call —
    meaning the plan a human reviewed via `secweave plan` beforehand was
    NOT necessarily what actually got executed. SPEC §5.1's own step
    sequence (bước 5 "Plan & dry-run" produces "Action plan trong
    allowlist" as its output, which bước 6 "Execute" then runs — no LLM
    call happens between them) assumes the plan flows through unchanged;
    `--plan-file` restores that property. Deliberately NOT stored in
    Context Store — SPEC §4.6 explicitly scopes that store to knowledge
    accumulated ACROSS runs (verified observations, rejected hypotheses,
    rule versions), not an in-flight execution artifact — a plain file
    matches how Authorization/the allowlist are already handled (operator-
    supplied, not persisted) for the very same Gate-3-shaped reason.

    Returns None (error already printed) on any failure. `args.hypothesis_id`
    is cross-checked against BOTH the file's own top-level hypothesis_id
    AND the embedded ActionPlan.hypothesis_id — real gap found via
    independent review: only the top-level one used to be checked, so a
    hand-edited or corrupted file with the two disagreeing (top-level
    matches --hypothesis-id, but plan_result.plan.hypothesis_id names a
    DIFFERENT hypothesis) loaded and executed with zero error, silently
    attributing another hypothesis's actions to this one. This doesn't
    check against ground truth in Context Store either (the whole point of
    --plan-file is to avoid needing that lookup) — it's self-consistency
    between what the file claims, not proof the hypothesis_id is real.
    """
    try:
        plan_data = json.loads(Path(args.plan_file).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"error: không tìm thấy plan file '{args.plan_file}'", file=sys.stderr)
        return None
    except OSError as exc:
        print(f"error: không đọc được plan file '{args.plan_file}': {exc}", file=sys.stderr)
        return None
    except json.JSONDecodeError as exc:
        print(f"error: plan file '{args.plan_file}' không phải JSON hợp lệ: {exc}", file=sys.stderr)
        return None

    if not isinstance(plan_data, dict) or plan_data.get("hypothesis_id") != args.hypothesis_id:
        print(
            f"error: plan file '{args.plan_file}' được lập cho hypothesis_id "
            f"'{plan_data.get('hypothesis_id') if isinstance(plan_data, dict) else '?'}', không khớp "
            f"--hypothesis-id đã truyền ('{args.hypothesis_id}') — có thể đang dùng nhầm file plan.",
            file=sys.stderr,
        )
        return None

    plan_result_data = plan_data.get("plan_result")
    if not isinstance(plan_result_data, dict):
        print(f"error: plan file '{args.plan_file}' thiếu field 'plan_result'.", file=sys.stderr)
        return None

    try:
        plan_result = ActionPlanResult(**plan_result_data)
    except ValidationError as exc:
        print(
            f"error: plan file '{args.plan_file}' có 'plan_result' không đúng schema ActionPlanResult: "
            f"{exc}",
            file=sys.stderr,
        )
        return None

    if plan_result.plan is not None and plan_result.plan.hypothesis_id != args.hypothesis_id:
        print(
            f"error: plan file '{args.plan_file}': plan_result.plan.hypothesis_id "
            f"('{plan_result.plan.hypothesis_id}') không khớp --hypothesis-id đã truyền "
            f"('{args.hypothesis_id}') — dù hypothesis_id ở cấp ngoài của file khớp, ActionPlan bên "
            "trong lại thuộc về 1 hypothesis khác. Có thể file đã bị sửa tay hoặc ghép nhầm.",
            file=sys.stderr,
        )
        return None

    print(f"-> Dùng lại plan ĐÃ ĐÓNG BĂNG từ '{args.plan_file}' (không gọi LLM lại).")
    return plan_result


def cmd_execute(args: argparse.Namespace) -> int:
    """Thực thi THẬT các action đã approve của 1 plan — nối KillSwitch/
    CostService/EvidenceHarness vào CLI, thứ 3 thành phần này trước đó chỉ
    chạy được qua script thủ công (.secweave/manual_test/*.py), chưa từng
    có entrypoint CLI/API thật nào (real gap tìm được qua review toàn dự
    án). Mỗi action approve được capture với role=MAIN — SCOPE THẬT: lệnh
    này không tự dựng được kịch bản 3-role (main/positive_control/
    denied_control), vì ActionSpec chưa có field nào đánh dấu 1 action
    đóng vai trò gì (gap đã biết, xem shared/models/observation.py) — muốn
    kịch bản đủ 3 role vẫn cần script tự viết như
    .secweave/manual_test/identity_scenario_example.py. decide() vẫn được
    gọi ở cuối để verdict thật ra đúng INCONCLUSIVE khi thiếu 2 nhóm kia,
    thay vì giả vờ có thể kết luận CONFIRMED/NOT_REPRODUCED từ 1 identity.

    `--plan-file`: dùng lại đúng plan đã `secweave plan` duyệt trước đó
    thay vì gọi LLM lập plan MỚI (xem _load_frozen_plan's docstring cho lý
    do). Không truyền cờ này vẫn hoạt động như trước — tiện cho test nhanh
    1 bước — nhưng KHÔNG đảm bảo plan thực thi giống plan đã xem qua
    `secweave plan` trước đó, vì LLM không xác định.
    """
    if args.plan_file:
        plan_result = _load_frozen_plan(args)
        if plan_result is None:
            return 1
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
        try:
            context_store = SecurityContextStore(db_path=args.context_db)
        except sqlite3.Error as exc:
            print(f"error: không mở được Context Store tại '{args.context_db}': {exc}", file=sys.stderr)
            return 1

        try:
            record = context_store.get_hypothesis(args.hypothesis_id)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
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

    if plan_result.status == ActionPlanStatus.NOT_PLANNABLE:
        print(f"NOT_PLANNABLE — {plan_result.reason}")
        return 0

    print(
        "CẢNH BÁO: authorization dùng để check dưới đây CHỈ dựng tạm để test cục bộ từ "
        "--allowed-action — KHÔNG phải Gate 2/3 thật đã duyệt. Lệnh này SẼ GỬI REQUEST THẬT tới "
        "các host trong allowlist — chỉ chạy khi bạn thực sự được phép làm điều đó trên target đó.",
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
        print(
            f"error: execution '{execution_id}' đã STOPPED trước đó — không tự động tiếp tục "
            "(SPEC §6.4 control #10: không tiếp tục sau stop-work trigger nếu chưa được cho phép "
            f"chạy lại). Chạy `secweave resume --execution-id {execution_id} --storage-dir "
            f"{args.storage_dir} --authorization-reference '...'` trước, rồi execute lại.",
            file=sys.stderr,
        )
        return 1
    # else: RUNNING — a prior `execute` for this execution_id already
    # started it; continue accumulating against the same KillSwitch/
    # CostService state rather than re-starting.

    cost_service = CostService(execution_id=execution_id, storage_dir=args.storage_dir, cap=args.cap)
    harness = EvidenceHarness(
        execution_id=execution_id,
        target_id=args.target_id,
        target_revision_id=args.target_revision_id,
        storage_dir=args.storage_dir,
        kill_switch=kill_switch,
        cost_service=cost_service,
    )

    print(f"-> execution_id: {execution_id}")
    print(
        f"-> Đang thực thi {len(plan_result.plan.actions)} action đã approve (identity="
        f"'{args.identity}', role=main cho tất cả — xem docstring cmd_execute về giới hạn này)..."
    )

    observations = []
    stopped_reason = None
    try:
        for check in review.plan_check.checks:
            try:
                observation = harness.capture(check.action, role=ObservationRole.MAIN, identity=args.identity)
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
            print(
                f"   [{observation.access_result.value}] {check.action.method} {check.action.target} "
                f"(HTTP {observation.status_code})"
            )
    finally:
        harness.close()

    print(f"-> Kill-switch status cuối: {kill_switch.status.value}")
    print(f"-> Cost: {cost_service.executed_action_count}/{cost_service.cap}")

    if observations:
        execution_status = ExecutionStatus.STOPPED if stopped_reason else ExecutionStatus.COMPLETED
        result = decide(observations, execution_status=execution_status)
        print(f"-> Verdict: {result.verdict.value}")
        print(f"   {result.reason}")

    return 1 if stopped_reason else 0


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
        source = StopSource(args.source)
    except ValueError:
        valid = ", ".join(s.value for s in StopSource)
        print(f"error: --source không hợp lệ '{args.source}' — chỉ chấp nhận: {valid}", file=sys.stderr)
        return 1

    automatic_threshold_reason = None
    if args.automatic_threshold_reason:
        try:
            automatic_threshold_reason = AutomaticThresholdReason(args.automatic_threshold_reason)
        except ValueError:
            valid = ", ".join(r.value for r in AutomaticThresholdReason)
            print(
                f"error: --automatic-threshold-reason không hợp lệ "
                f"'{args.automatic_threshold_reason}' — chỉ chấp nhận: {valid}",
                file=sys.stderr,
            )
            return 1

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
        print(f"error: {exc}", file=sys.stderr)
        return 1

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
    kill_switch = KillSwitch(execution_id=args.execution_id, storage_dir=args.storage_dir)
    try:
        kill_switch.resume(actor=args.actor, authorization_reference=args.authorization_reference)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

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
        help='1 entry allowlist, dạng "METHOD https://host/path/{param} [params:key1,key2]" — có thể '
        "lặp lại flag này nhiều lần để cấp nhiều entry. Không truyền = allowlist rỗng = mọi action đều "
        "bị chặn. Phần 'params:...' tuỳ chọn: liệt kê tên field được phép xuất hiện trong "
        "ActionSpec.parameters (query string hoặc JSON body) của action đó — không ghi thì mặc định "
        "action PHẢI có parameters rỗng, không phải 'cho phép tất cả'.",
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
        '{param} [params:key1,key2]", lặp lại flag để cấp nhiều entry.',
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
