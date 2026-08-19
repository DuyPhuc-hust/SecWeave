import argparse
import json
import re
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar

import httpx
from pydantic import BaseModel, Field, ValidationError

from context_store.store import DEFAULT_DB_PATH, SecurityContextStore
from evidence_harness.harness import EvidenceHarness
from exploit_agent.agent import ExploitAgent
from hypothesis_engine.engine import HypothesisEngine
from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from shared.cost import CostService
from shared.id_generator import generate_id
from shared.kill_switch import AutomaticThresholdReason, KillSwitch, StopSource
from shared.models.action import ActionPlanResult, ActionPlanStatus, ActionSpec, ActionType
from shared.models.entities import Authorization, AuthorizationLayer
from shared.models.hypothesis import Hypothesis, HypothesisProvenance, HypothesisStatus
from shared.models.kill_switch import ExecutionStatus
from shared.models.observation import BLIND_MARKER_PLACEHOLDER, NormalizedObservation, ObservationRole
from shared.models.signal import NormalizedSignal, SignalCoverage
from shared.models.verification_package import Environment, ReviewDecision, VerificationPackage
from shared.policy import is_allowed
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
            context_store.get_verified_context(args.target_id, args.target_revision_id)
            if args.target_id
            else []
        )
        # SPEC §4.6 write-path diagram's dashed arrow: "unverified: chỉ tra
        # cứu, có nhãn cảnh báo" — a real, sanctioned read pathway, not a
        # future TODO. build_prompt() labels this separately from
        # verified_context so the LLM can't mistake "captured once, never
        # reviewed" for confirmed fact.
        unverified_context = (
            context_store.get_unverified_context(args.target_id, args.target_revision_id)
            if args.target_id
            else []
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


def _load_hypothesis_from_context_store(
    context_store: SecurityContextStore,
    hypothesis_id: str,
    current_target_id: Optional[str] = None,
    current_revision: Optional[str] = None,
) -> Hypothesis:
    """Looks up a stored Hypothesis by id, raising CliError on any failure
    (not found, store error, or a schema mismatch while reconstructing
    it) — shared by `plan` and `execute` (without --plan-file), both of
    which start from a stored hypothesis_id the same way. Closes
    `context_store` once the lookup itself is done, before the
    (network-free) reconstruction step.

    `current_target_id`/`current_revision` (the target/revision the CALLER
    is about to plan/execute against — optional since `plan` doesn't
    require them) enable a WARNING, not a hard block, if they differ from
    what was recorded when this hypothesis was generated (real gap found
    via independent review of the verified_observations revision-
    staleness fix — the same class of gap exists one tier up: a hypothesis
    carries no memory of what it was generated for). A warning rather than
    a CliError deliberately: re-testing an OLD hypothesis against a NEWER
    revision on purpose (e.g. confirming a fix landed) is a legitimate
    workflow WEEKLY_PLAN W7 itself describes — this must not block it,
    only make the operator aware. Only compared when BOTH sides are known
    (a NULL/None on either side means nothing to compare against, not a
    mismatch).

    Real gap found via independent review: an empty string (`""`) is just
    as falsy as `None` in the comparison below, so a caller passing
    `--target-id ""`/`--target-revision-id ""` (e.g. an unset shell
    variable interpolated into a script) would silently skip the cross-
    check entirely — no warning, no error — indistinguishable from the
    flag never being passed at all. Since this feature's only job IS
    emitting that warning, treated as a caller mistake worth surfacing
    explicitly rather than a legitimate "nothing to compare" case (which
    only `None` — the flag genuinely omitted — means).
    """
    if current_target_id == "":
        raise CliError("target_id truyền vào để đối chiếu không được là chuỗi rỗng — bỏ hẳn cờ nếu không cần.")
    if current_revision == "":
        raise CliError("revision truyền vào để đối chiếu không được là chuỗi rỗng — bỏ hẳn cờ nếu không cần.")

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

    stored_target_id = record.get("target_id")
    stored_revision = record.get("revision")
    if stored_target_id and current_target_id and stored_target_id != current_target_id:
        print(
            f"CẢNH BÁO: hypothesis '{hypothesis_id}' được sinh cho target_id='{stored_target_id}', khác "
            f"với target_id hiện tại '{current_target_id}' — kết quả có thể không còn liên quan.",
            file=sys.stderr,
        )
    elif stored_revision and current_revision and stored_revision != current_revision:
        print(
            f"CẢNH BÁO: hypothesis '{hypothesis_id}' được sinh khi target ở revision '{stored_revision}', "
            f"khác với revision hiện tại '{current_revision}' — code target có thể đã đổi từ lúc đó, cân "
            "nhắc sinh lại hypothesis mới từ signal gốc thay vì dùng bản cũ này.",
            file=sys.stderr,
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


class _IdentityLoginSpec(BaseModel):
    """One entry of a `--identity-logins` file — a plain serialization of
    `EvidenceHarness.login()`'s own parameters (shared/evidence_harness/
    harness.py), so this model carries no target-specific logic of its
    own: method/target/parameters describe THIS target's login request
    shape, token_json_path/token_header/token_prefix describe how to pull
    a bearer token out of the response (all optional — omit token_json_path
    entirely for a cookie-based target, where httpx's own client jar
    already handles the session with no extra config needed).
    """

    method: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None
    token_json_path: Optional[str] = None
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "


def _parse_role_identity_args(raw: Optional[List[str]]) -> Dict[ObservationRole, str]:
    """Parses repeated `--role-identity ROLE=LABEL` entries into a role ->
    identity-label map — the mechanism that lets a 3-role plan (ActionSpec.
    role, see shared/models/action.py) actually run each role under a
    DIFFERENT identity, without Exploit Agent/the LLM ever having to name or
    choose a real identity itself (SPEC §4.2: "không tự lấy credential" —
    identity comes from the operator, only ROLE comes from the plan).
    `LABEL` is just a string key into `--identity-logins` (or nothing, if
    that identity is meant to run unauthenticated) — never a real
    credential itself.
    """
    result: Dict[ObservationRole, str] = {}
    for entry in raw or []:
        if "=" not in entry:
            raise CliError(
                f"--role-identity không hợp lệ '{entry}' — cần đúng dạng 'ROLE=LABEL', vd "
                "'positive_control=owner'."
            )
        role_raw, label = entry.split("=", 1)
        role = _parse_enum_arg(ObservationRole, role_raw, f"--role-identity (phần ROLE của '{entry}')")
        if not label:
            raise CliError(f"--role-identity '{entry}' có LABEL rỗng — cần 1 tên identity không rỗng.")
        result[role] = label
    return result


def _load_identity_logins(path: Optional[str]) -> Dict[str, _IdentityLoginSpec]:
    """Loads a `--identity-logins` file — a JSON object keyed by identity
    label, each value an `_IdentityLoginSpec`. Returns {} when `path` is
    None (the common case: no multi-identity login needed), so callers
    never need a separate None-check before doing a dict lookup."""
    if not path:
        return {}
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CliError(f"không tìm thấy --identity-logins file '{path}'")
    except json.JSONDecodeError as exc:
        raise CliError(f"--identity-logins file '{path}' không phải JSON hợp lệ: {exc}") from exc

    if not isinstance(raw, dict):
        raise CliError(f"--identity-logins file '{path}' phải là 1 JSON object (label -> cấu hình login).")

    try:
        return {label: _IdentityLoginSpec(**cfg) for label, cfg in raw.items()}
    except ValidationError as exc:
        raise CliError(f"--identity-logins file '{path}' có entry không đúng schema: {exc}") from exc


def _replace_placeholder_recursive(value: Any, marker: str) -> Any:
    """Walks `value` — a plain string, or any JSON-shaped nesting of
    dict/list around strings (exactly what LLM JSON output can ever
    produce) — replacing every occurrence of BLIND_MARKER_PLACEHOLDER
    with `marker`. Real gap found via independent review: an earlier
    version only substituted TOP-LEVEL STRING values of
    action.parameters — a not-perfectly-obedient LLM (this codebase has
    documented real cases of one ignoring instructions) putting the
    placeholder in action.target/description, or nesting it inside a
    dict/list value within parameters, would sail through un-substituted
    with NO error — the real target would silently receive the literal
    placeholder text instead of a real marker, and nobody would notice
    short of reading the raw transcript by hand. Recursing over every
    field (see `_action_field_values_for_marker_scan`) closes that."""
    if isinstance(value, str):
        return value.replace(BLIND_MARKER_PLACEHOLDER, marker)
    if isinstance(value, dict):
        return {key: _replace_placeholder_recursive(v, marker) for key, v in value.items()}
    if isinstance(value, list):
        return [_replace_placeholder_recursive(v, marker) for v in value]
    return value


def _contains_placeholder_recursive(value: Any) -> bool:
    if isinstance(value, str):
        return BLIND_MARKER_PLACEHOLDER in value
    if isinstance(value, dict):
        return any(_contains_placeholder_recursive(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_placeholder_recursive(v) for v in value)
    return False


def _action_field_values_for_marker_scan(action: ActionSpec) -> List[Any]:
    """Every field of `action` the placeholder could plausibly end up in —
    not just `parameters` (see `_replace_placeholder_recursive`'s
    docstring for why scanning only `parameters`' top-level string values
    was a real gap)."""
    return [action.target, action.description, action.method, action.parameters]


def _uses_blind_marker_placeholder(actions: List[ActionSpec]) -> bool:
    """True if any action anywhere contains BLIND_MARKER_PLACEHOLDER —
    Exploit Agent's own signal (taught in its prompt) that this plan opted
    into a blind-marker 3-role scenario (SPEC §4.3.4)."""
    return any(
        _contains_placeholder_recursive(value)
        for action in actions
        for value in _action_field_values_for_marker_scan(action)
    )


def _substitute_blind_marker(action: ActionSpec, marker: str) -> ActionSpec:
    """Replaces BLIND_MARKER_PLACEHOLDER with the REAL marker EVERYWHERE
    in `action` (target/description/method/parameters, recursively) —
    called on every action in a plan that uses the placeholder anywhere
    (not just the role=setup one), in case a future prompt ever has a
    legitimate reason to reference it from more than one action. A no-op
    for any action that doesn't contain the placeholder at all.

    Verifies afterward that NOTHING is left un-substituted — a defensive
    check that should be unreachable given the recursion above covers
    every JSON-representable shape action.parameters can take, but a
    silent partial substitution (the real target receiving the literal
    placeholder text instead of a real marker) is exactly the failure
    mode a future refactor missing a field must fail LOUDLY on, not
    quietly reproduce.
    """
    substituted = action.model_copy(
        update={
            "target": _replace_placeholder_recursive(action.target, marker),
            "description": _replace_placeholder_recursive(action.description, marker),
            "method": _replace_placeholder_recursive(action.method, marker),
            "parameters": _replace_placeholder_recursive(action.parameters, marker),
        }
    )
    if any(_contains_placeholder_recursive(v) for v in _action_field_values_for_marker_scan(substituted)):
        raise CliError(
            f"action_id='{action.action_id}': placeholder blind marker vẫn còn sau khi thay thế — lỗi "
            "nội bộ không nên xảy ra, báo lại kèm plan gốc."
        )
    return substituted


# Resource-ID-chaining (2026-08-19): lets a LATER action reference a REAL
# value from an EARLIER action's own response within the same plan — e.g.
# a server-assigned resource ID that doesn't exist until the earlier
# action actually ran. Exploit Agent's prompt teaches the LLM to tag the
# earlier action with a `step_id` and embed this exact placeholder syntax
# in a later action's target/parameters; the LLM never guesses the real
# value (SPEC's same "no fabricated runtime facts" principle the blind-
# marker mechanism above already enforces for a different value).
_FROM_STEP_PATTERN = re.compile(r"\{\{FROM_STEP:([A-Za-z0-9_-]+):([^{}]+)\}\}")


def _resolve_json_path(data: Any, path: str) -> Any:
    """Same dotted-path convention as EvidenceHarness.login()'s own
    token_json_path (numeric segments index into a list) — one syntax to
    learn across both features. Raises KeyError/TypeError/IndexError on a
    bad path, left uncaught here so callers can add their own context."""
    value = data
    for part in path.split("."):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def _load_step_response_body(observation: NormalizedObservation) -> Any:
    """Reads back the REAL captured response body for an action tagged
    with step_id, so a later action can reference it. Raises ValueError
    if the raw evidence has no response body at all, or the body isn't
    JSON — a step_id was declared for a reason, so failing loudly now
    (rather than deferring to whatever later action tries to reference
    it) surfaces the real problem at the point it actually happened."""
    raw = json.loads(Path(observation.raw_evidence_ref).read_text(encoding="utf-8"))
    body = raw.get("response", {}).get("body")
    if body is None:
        raise ValueError(f"observation '{observation.observation_id}' (step_id) không có response body.")
    return json.loads(body)


def _lookup_from_step(step_id: str, path: str, step_responses: Dict[str, Any]) -> Any:
    if step_id not in step_responses:
        raise CliError(
            f"action tham chiếu '{{{{FROM_STEP:{step_id}:{path}}}}}' nhưng step_id='{step_id}' chưa "
            "chạy (hoặc không tồn tại) tính đến thời điểm này trong plan — FROM_STEP chỉ được tham "
            "chiếu action đứng TRƯỚC trong cùng plan, không tham chiếu ngược hay tự tham chiếu."
        )
    try:
        return _resolve_json_path(step_responses[step_id], path)
    except (KeyError, TypeError, IndexError, ValueError) as exc:
        raise CliError(
            f"'{{{{FROM_STEP:{step_id}:{path}}}}}': không trích được giá trị từ response thật của step "
            f"'{step_id}' — {type(exc).__name__}: {exc}"
        ) from exc


def _resolve_from_step_in_string(text: str, step_responses: Dict[str, Any]) -> str:
    """For target/description (always plain strings) — every match is
    stringified and interpolated into the surrounding text. Real gap
    found via independent review: a resolved value that's itself a
    dict/list (a json_path pointing at a nested object rather than a
    scalar) used to be silently `str()`-ed into the URL/description —
    Python's dict repr embedded literally in a URL is nonsense, not
    something a plan author could have meant. Rejected explicitly instead
    of producing a garbled request (harness.capture() DOES already catch
    an invalid URL and record a failed observation rather than crashing,
    but failing here is clearer and doesn't waste a real HTTP attempt/cost
    slot on a request that could never have been meaningful).
    """

    def _sub(match: re.Match) -> str:
        resolved = _lookup_from_step(match.group(1), match.group(2), step_responses)
        if isinstance(resolved, (dict, list)):
            raise CliError(
                f"'{{{{FROM_STEP:{match.group(1)}:{match.group(2)}}}}}' trong target/description trỏ "
                f"tới 1 object/list ({type(resolved).__name__}), không phải giá trị đơn (string/số/bool) "
                "— không thể nhúng thẳng vào URL hay mô tả dạng text."
            )
        return str(resolved)

    return _FROM_STEP_PATTERN.sub(_sub, text)


def _resolve_from_step_in_value(value: Any, step_responses: Dict[str, Any]) -> Any:
    """For `parameters` (arbitrary JSON) — a value that's EXACTLY one
    placeholder (nothing else around it) resolves to the referenced
    value's OWN type (e.g. a real int stays an int, useful when a target
    API expects a numeric ID in the JSON body, not a stringified one);
    a placeholder embedded inside a larger string is stringified and
    interpolated, same as target/description."""
    if isinstance(value, dict):
        return {key: _resolve_from_step_in_value(v, step_responses) for key, v in value.items()}
    if isinstance(value, list):
        return [_resolve_from_step_in_value(v, step_responses) for v in value]
    if not isinstance(value, str):
        return value
    exact = _FROM_STEP_PATTERN.fullmatch(value)
    if exact:
        return _lookup_from_step(exact.group(1), exact.group(2), step_responses)
    return _resolve_from_step_in_string(value, step_responses)


def _resolve_from_step_references(action: ActionSpec, step_responses: Dict[str, Any]) -> ActionSpec:
    """Called on every action right before it executes (a no-op if it has
    no FROM_STEP reference anywhere — the regex simply never matches)."""
    return action.model_copy(
        update={
            "target": _resolve_from_step_in_string(action.target, step_responses),
            "description": _resolve_from_step_in_string(action.description, step_responses),
            "parameters": _resolve_from_step_in_value(action.parameters, step_responses),
        }
    )


def cmd_execute(args: argparse.Namespace) -> int:
    """Thực thi THẬT các action đã approve của 1 plan — nối KillSwitch/
    CostService/EvidenceHarness vào CLI, thứ 3 thành phần này trước đó chỉ
    chạy được qua script thủ công (.secweave/manual_test/*.py), chưa từng
    có entrypoint CLI/API thật nào (real gap tìm được qua review toàn dự
    án). Mỗi action được capture với đúng `action.role` mà Exploit Agent đã
    gắn cho nó khi lập plan (ActionSpec.role, mặc định main nếu plan không
    tự gắn role nào khác) — không còn hardcode role=main cho mọi action như
    trước (2026-08-19: đóng phần "role tagging" của gap 3-role).

    2026-08-19 (tiếp): đóng phần "multi-identity" — `--role-identity
    ROLE=LABEL` (lặp lại được) ánh xạ 1 role sang 1 identity LABEL khác
    `--identity` mặc định; `--identity-logins <file>` khai credential thật
    (method/target/parameters/token_json_path) cho từng LABEL, được
    `harness.login()` thật TRƯỚC khi plan chạy, cho phép positive_control
    đọc bằng chính danh tính chủ sở hữu và denied_control đọc bằng danh
    tính khác, đúng nghĩa 3-role, trong CÙNG 1 lượt `execute`. Exploit
    Agent vẫn không hề chạm vào credential thật — plan chỉ mang `role`,
    LABEL/credential hoàn toàn do operator cấp qua CLI. LABEL không có
    entry trong `--identity-logins` vẫn chạy được, chỉ là không đăng nhập
    (client mới, chưa có session) — một identity ẩn danh hợp lệ.

    2026-08-19 (tiếp): đóng phần "blind marker seeding" — gap con thứ 3/3
    cuối cùng của kịch bản 3-role. Nếu plan có action nào chứa
    `BLIND_MARKER_PLACEHOLDER` (shared/models/observation.py) trong
    parameters — dấu hiệu Exploit Agent đã thiết kế 1 action `role=setup`
    seed dữ liệu mồi — lệnh này tự gọi `EvidenceHarness.generate_marker()`
    lấy marker THẬT rồi thay placeholder bằng marker thật trong TOÀN BỘ
    action's parameters, TRƯỚC `review_plan()` (để Policy Service kiểm
    đúng giá trị thật sẽ gửi, không phải placeholder), rồi truyền
    `marker=` thật vào mọi `capture()` — nhờ đó "main" giờ có thể thật sự
    SATISFIED, không còn luôn INSUFFICIENT_DATA. Exploit Agent/LLM không
    bao giờ thấy giá trị marker thật, chỉ biết đúng 1 placeholder công
    khai cố định (SPEC §4.3.4: "Exploit Agent / mọi LLM: Không" biết
    marker). Plan không dùng placeholder thì hành vi y hệt trước đây
    (`marker=None`, không tự sinh `seed_manifest.json`). decide() vẫn được
    gọi ở cuối để verdict thật ra đúng INCONCLUSIVE khi thiếu nhóm
    predicate nào đó, thay vì giả vờ có thể kết luận CONFIRMED/
    NOT_REPRODUCED khi thiếu bằng chứng.

    2026-08-19 (tiếp): thêm resource-ID-chaining — `{{FROM_STEP:<step_id>:
    <json_path>}}` trong target/parameters của 1 action được tự resolve
    bằng giá trị THẬT trích từ response thật của action `step_id` đã chạy
    TRƯỚC nó trong cùng plan (vd 1 note vừa tạo, server tự cấp ID, action
    sau cần đọc lại đúng note đó). Khác blind marker (resolve 1 lần, trước
    review_plan()) — cái này BẮT BUỘC resolve XEN KẼ trong vòng lặp capture
    chính, vì giá trị thật chỉ tồn tại sau khi action nguồn đã thực sự
    chạy; Policy Service vẫn kiểm được plan chưa resolve vì cú pháp
    `{param}` trong allowlist vốn đã khớp bất kỳ text nào ở 1 path segment,
    kể cả text `{{FROM_STEP:...}}` chưa resolve. `actions.json` được ghi
    lại LẦN 2 cho từng action ngay khi nó chạy xong, đè lên bản chưa
    resolve đã ghi lúc đầu (đổi `_persist_actions()` sang "action_id trùng
    thì bản mới thắng"). Tham chiếu tới step_id chưa chạy (chưa tới lượt,
    hoặc gõ sai) → `CliError` sạch, không silently gửi text placeholder
    tới target thật.

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
    # Real gap found via independent review: argparse's required=True on
    # --target-revision-id only checks the FLAG was passed, not that its
    # VALUE is non-empty — `--target-revision-id ""` used to sail through
    # here, then crash with an unhandled ValueError the moment the first
    # action's capture() tried to write it to Context Store
    # (record_unverified_observation's own _require_revision check,
    # deliberately NOT swallowed by capture()'s best-effort
    # `except RuntimeError: pass`, since silently dropping a config
    # mistake would defeat the whole point of validating it). Checked
    # here, once, up front — a clean CliError before any real HTTP
    # request instead of a raw traceback mid-run.
    if not args.target_revision_id:
        raise CliError("--target-revision-id không được để trống.")

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

    if plan_result.status == ActionPlanStatus.NOT_PLANNABLE:
        print(f"NOT_PLANNABLE — {plan_result.reason}")
        return 0

    execution_id = args.execution_id or generate_id("exec")

    # Blind marker (SPEC §4.3.4): a plan that opted into a 3-role blind-
    # marker scenario (Exploit Agent's prompt teaches it to embed
    # BLIND_MARKER_PLACEHOLDER in exactly the bait-data parameter it wants
    # checked) gets that placeholder swapped for a REAL random marker HERE
    # — after the LLM is completely done, and BEFORE Policy Service/Cost
    # Service/execution ever see the plan — so the real marker value never
    # passes through any LLM context (SPEC's own table: "Exploit Agent /
    # mọi LLM: Không" biết marker). Substituting before review_plan() below
    # (not after) matters for a real reason, not just tidiness: an
    # allowlist entry with `params:key=regex` on this parameter is checked
    # against the REAL marker's shape (32 hex chars from
    # EvidenceHarness.generate_marker()), not the placeholder text — the
    # only way that check can mean anything.
    marker_value = None
    if _uses_blind_marker_placeholder(plan_result.plan.actions):
        # A throwaway EvidenceHarness — no kill_switch/cost_service/
        # http_client wired in — used ONLY to call generate_marker(),
        # which needs nothing but execution_id/storage_dir/target
        # metadata and never opens an httpx.Client (that's lazy, on first
        # capture()/login() call, neither of which happens here). The
        # REAL EvidenceHarness constructed later reuses the same
        # execution_id/storage_dir, so generate_marker()'s own
        # idempotent-per-execution_id seed manifest means this throwaway
        # instance and the real one always agree on the same value.
        marker_value = EvidenceHarness(
            execution_id=execution_id,
            target_id=args.target_id,
            target_revision_id=args.target_revision_id,
            storage_dir=args.storage_dir,
        ).generate_marker()
        plan_result.plan.actions = [
            _substitute_blind_marker(action, marker_value) for action in plan_result.plan.actions
        ]

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

    # Parsed BEFORE any KillSwitch/CostService/EvidenceHarness state is
    # created below — a malformed --role-identity/--identity-logins is a
    # config problem, same class as a malformed --plan-file, and should
    # fail before anything gets a chance to start/consume cost budget.
    role_identity = _parse_role_identity_args(args.role_identity)
    identity_logins = _load_identity_logins(args.identity_logins)

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

    actions_path = harness_storage_dir / "actions.json"

    def _persist_actions(new_actions: List[ActionSpec]) -> None:
        # Persisted so a later, separate `secweave assemble-package`
        # invocation can reconstruct VerificationPackage's `actions` input
        # (SPEC §7 field #9) without needing the original --plan-file to
        # still be lying around. MERGED with whatever's already on disk (by
        # action_id), not overwritten wholesale — real gap found via
        # independent review: reusing one execution_id across multiple
        # `execute` calls with DIFFERENT plans is an explicitly supported
        # pattern elsewhere in this codebase (kill-switch RUNNING-
        # continuation branch, CostService cap accumulation — see this
        # function's own comment above on kill_switch.status), and
        # observations.jsonl already accumulates across such calls.
        # Overwriting actions.json with only THIS invocation's actions
        # permanently and unrecoverably broke `assemble-package` for
        # exactly that pattern — an earlier call's ActionSpec, still
        # referenced by an earlier observation's action_ref, would vanish
        # from the file entirely.
        #
        # A matching action_id WRITES OVER the existing entry (not
        # skipped) — needed for resource-ID-chaining: the same action_id
        # gets persisted TWICE within one invocation, once upfront still
        # carrying its unresolved {{FROM_STEP:...}} text (in case a run
        # stops before reaching it), then again with the REAL resolved
        # value right as it's captured — the resolved version must win.
        # Harmless for the cross-invocation case this was built for too:
        # the same auto-generated action_id reappearing across 2 different
        # `execute` calls only happens by re-using the exact same
        # --plan-file, so the "newer" content is never a genuinely
        # different action being confused for an old one.
        existing_actions_raw = json.loads(actions_path.read_text(encoding="utf-8")) if actions_path.exists() else []
        by_action_id = {item["action_id"]: item for item in existing_actions_raw}
        for action in new_actions:
            by_action_id[action.action_id] = action.model_dump(mode="json")
        actions_path.write_text(json.dumps(list(by_action_id.values()), indent=2), encoding="utf-8")

    _persist_actions(plan_result.plan.actions)

    print(f"-> execution_id: {execution_id}")
    role_identity_desc = ", ".join(f"{role.value}={label}" for role, label in role_identity.items())
    print(
        f"-> Đang thực thi {len(plan_result.plan.actions)} action đã approve — mỗi action tự mang role "
        f"riêng do Exploit Agent gắn (mặc định main). Identity: '{args.identity}' cho role không có "
        f"--role-identity riêng"
        + (f", {role_identity_desc} cho role có khai báo riêng" if role_identity_desc else "")
        + "..."
    )

    # Parameter names whose VALUES must never be written to the raw evidence
    # transcript — see EvidenceHarness.capture()'s docstring. Passed to
    # login() calls too (below), so a password declared once here is
    # redacted everywhere, not just in the main capture loop.
    sensitive_body_keys = set(args.sensitive_param or [])
    observations = []
    stopped_reason = None
    # Resource-ID-chaining: step_id -> that action's REAL parsed response
    # body, populated as each step_id-tagged action actually executes (see
    # _resolve_from_step_references). Empty for the overwhelming majority
    # of plans that never use {{FROM_STEP:...}} at all.
    step_responses: Dict[str, Any] = {}

    def _persist_observation(observation: NormalizedObservation) -> None:
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
        observations.append(observation)
        observations_log_path = harness_storage_dir / "observations.jsonl"
        with open(observations_log_path, "a", encoding="utf-8") as f:
            f.write(observation.model_dump_json() + "\n")

    try:
        # Every identity label actually referenced by THIS plan's own
        # actions (the default --identity, plus any --role-identity
        # override whose role actually appears in plan_result.plan.actions)
        # that ALSO has a --identity-logins entry gets logged in now, once,
        # before any of the plan's own actions run — a label with NO login
        # entry simply runs unauthenticated (EvidenceHarness gives it a
        # fresh client on first use), a legitimate identity too (e.g. an
        # anonymous, never-logged-in denied_control). Real gap found via
        # independent review: an EARLIER version of this filtered only by
        # "referenced by --role-identity at all", not by whether that role
        # is actually used in THIS plan — a --role-identity entry for a
        # role this plan happens not to use would still trigger a real
        # login HTTP request (consuming CostService budget, possibly
        # tripping the cost cap) for an identity nothing here would ever
        # send a single action as.
        roles_in_plan = {action.role for action in plan_result.plan.actions}
        relevant_labels = {label for role, label in role_identity.items() if role in roles_in_plan}
        identities_needing_login = sorted({args.identity, *relevant_labels} & identity_logins.keys())
        for label in identities_needing_login:
            login_spec = identity_logins[label]
            login_action = ActionSpec(
                type=ActionType.TEST_DATA_CREATION,
                method=login_spec.method,
                target=login_spec.target,
                description=login_spec.description or f"Log in as identity '{label}'.",
                parameters=login_spec.parameters,
                # Real gap found while running this end-to-end: without
                # this, ActionSpec.role defaulted to MAIN — but
                # harness.login() ALWAYS internally captures with
                # role=SETUP regardless of what the ActionSpec itself
                # says, so the persisted action_record entry would claim
                # role=main for an action whose own observation says
                # role=setup — a confusing, misleading mismatch for
                # anyone reading the assembled package later.
                role=ObservationRole.SETUP,
            )
            # Real gap found while running this end-to-end: login_action's
            # action_id is freshly auto-generated here (ActionSpec.action_id
            # defaults to a new id, never supplied by the operator) and
            # NEVER appeared anywhere in plan_result.plan.actions — so
            # without this call, assemble-package would later reject the
            # WHOLE package with "action_record thiếu ActionSpec cho
            # action_ref" the moment it tried to reconstruct action_record
            # for this login's own (role=setup) observation. Persisted
            # (not just attempted) even if the login itself fails below —
            # matches how plan_result.plan.actions is persisted regardless
            # of whether every one of them ends up producing an
            # observation.
            _persist_actions([login_action])
            try:
                login_observation = harness.login(
                    label,
                    login_action,
                    token_json_path=login_spec.token_json_path,
                    token_header=login_spec.token_header,
                    token_prefix=login_spec.token_prefix,
                    sensitive_request_keys=sensitive_body_keys,
                )
            except RuntimeError as exc:
                # Same reasoning as the capture-loop's own RuntimeError
                # handling below — a login attempt goes through capture()
                # internally too, so it's subject to the exact same kill-
                # switch/cost-cap stop conditions mid-run.
                stopped_reason = str(exc)
                print(f"   DỪNG GIỮA CHỪNG (login '{label}'): {exc}", file=sys.stderr)
                break
            except ValueError as exc:
                # Distinct from RuntimeError above: a broken token_json_path
                # or an unusable extracted token is a CONFIG/setup mistake
                # (wrong path for this target, or --identity-logins itself
                # wrong) — not an operational stop a resume would fix the
                # same way, so this raises immediately (same class as
                # _load_frozen_plan/_build_llm_client's own setup failures)
                # instead of being folded into stopped_reason below.
                raise CliError(f"login() cho identity '{label}' thất bại: {exc}") from exc
            _persist_observation(login_observation)
            print(f"   [login] identity '{label}' — HTTP {login_observation.status_code}")

        if stopped_reason is None:
            for check in review.plan_check.checks:
                # Resource-ID-chaining: resolves any {{FROM_STEP:...}}
                # reference against REAL responses of already-executed
                # steps in THIS run — a no-op for the overwhelming
                # majority of actions that never use it. Raises CliError
                # (via _lookup_from_step) if the referenced step_id hasn't
                # run yet/doesn't exist, or its response can't be
                # traversed to the requested json path.
                resolved_action = _resolve_from_step_references(check.action, step_responses)
                # Real gap found via independent review: review_plan() above
                # only ever checked the UNRESOLVED plan against the
                # allowlist — a {{FROM_STEP:...}} placeholder has no "/" in
                # it, so it always satisfies an `{id}`-style path template's
                # `[^/]+` regex regardless of what the runtime-resolved
                # value turns out to be. Since that value comes from a
                # REAL, possibly attacker-influenced response (exactly the
                # kind of data an IDOR-style plan reads), a resolved value
                # like "42/../../admin/settings" could turn one path
                # segment into several, escaping the reviewed scope with
                # zero enforcement — a real, exploitable bypass, same class
                # already fixed once for percent-encoded path traversal.
                # Re-checking the ACTUALLY-RESOLVED action here — right
                # before it's sent, with the exact bytes that will go out —
                # closes it: deny-by-default applies to what's really sent,
                # not just to what the plan looked like on paper.
                resolved_decision = is_allowed(resolved_action, authorization)
                if not resolved_decision.allowed:
                    raise CliError(
                        f"action_id='{resolved_action.action_id}' sau khi resolve FROM_STEP không còn "
                        f"khớp allowlist: {resolved_decision.reason} — giá trị thật lấy từ response "
                        "runtime đã vượt phạm vi plan đã duyệt, từ chối gửi request thật."
                    )
                try:
                    observation = harness.capture(
                        resolved_action,
                        role=resolved_action.role,
                        marker=marker_value,
                        identity=role_identity.get(resolved_action.role, args.identity),
                        sensitive_body_keys=sensitive_body_keys,
                    )
                except RuntimeError as exc:
                    # Real gap found via independent review: catching only
                    # (ExecutionStoppedError, CostCapExceededError) missed a
                    # bare RuntimeError from CostService.record_action()'s
                    # own write-failure path (shared/cost.py) or KillSwitch's
                    # audit-log write failure (shared/kill_switch.py, now
                    # wrapped there too) — both ARE RuntimeError subclasses
                    # already, so catching the base class covers all 3
                    # uniformly instead of missing the 2 that aren't
                    # explicitly named here.
                    stopped_reason = str(exc)
                    print(f"   DỪNG GIỮA CHỪNG: {exc}", file=sys.stderr)
                    break
                _persist_observation(observation)
                # Persisted again here (action_id unchanged, only target/
                # description/parameters may differ) so actions.json ends
                # up holding the REAL resolved values, not the unresolved
                # {{FROM_STEP:...}} text from the upfront _persist_actions
                # call above — same reasoning as the blind-marker
                # substitution's own actions.json handling.
                _persist_actions([resolved_action])
                if resolved_action.step_id:
                    if resolved_action.step_id in step_responses:
                        # Real gap found via independent review: 2 actions
                        # reusing the same step_id (an LLM mistake — the
                        # prompt never explicitly forbids it) would
                        # silently let the SECOND one's response clobber
                        # the first in step_responses, so a later
                        # FROM_STEP reference resolves to whichever
                        # same-labeled action happened to run more
                        # recently, with no error — genuinely ambiguous
                        # which one a reference means, so refuse instead
                        # of silently picking one.
                        raise CliError(
                            f"step_id='{resolved_action.step_id}' được gán cho hơn 1 action trong cùng "
                            "plan — mỗi step_id chỉ được dùng đúng 1 lần, nếu không FROM_STEP tham "
                            "chiếu tới action nào sẽ không rõ ràng."
                        )
                    try:
                        step_responses[resolved_action.step_id] = _load_step_response_body(observation)
                    except ValueError as exc:
                        raise CliError(str(exc)) from exc
                print(
                    f"   [{observation.access_result.value}] {resolved_action.method} {resolved_action.target} "
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


def _read_verdict_for_execution(execution_id: str, storage_dir: str) -> Optional[str]:
    """Reads back observations.jsonl + execution_status.json for a
    previously-run `execute` execution_id and recomputes its verdict —
    exactly the artifacts `assemble-package` itself reads, but retest
    only needs a bare verdict string, not a full 19-field package (no
    human-authored scenario/limitations/next_action to fabricate 1 per
    retest run). Returns None if the execution captured no observations
    at all (e.g. stopped before anything ran) — a real, distinct outcome
    from any of the 3 named verdicts, not silently coerced into one.
    """
    execution_dir = Path(storage_dir) / execution_id
    observations_path = execution_dir / "observations.jsonl"
    status_path = execution_dir / "execution_status.json"
    if not observations_path.exists() or not status_path.exists():
        return None
    try:
        observations = [
            NormalizedObservation(**json.loads(line))
            for line in observations_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        execution_status = ExecutionStatus(json.loads(status_path.read_text(encoding="utf-8"))["execution_status"])
    except (json.JSONDecodeError, ValidationError, ValueError, OSError) as exc:
        raise CliError(f"không đọc được artifact của execution '{execution_id}': {exc}") from exc
    if not observations:
        return None
    return decide(observations, execution_status=execution_status).verdict.value


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
        verdict = _read_verdict_for_execution(run_execution_id, args.storage_dir)
        results.append((run_execution_id, verdict))
        print(f"-> Lần {i}/{args.runs}: verdict={verdict or '(không có observation — có thể đã bị dừng giữa chừng)'}")

    verdict_counts = Counter(v for _, v in results if v is not None)
    most_common_verdict, agree_count = verdict_counts.most_common(1)[0] if verdict_counts else (None, 0)
    ratio = agree_count / len(results)
    meets_threshold = ratio >= (2 / 3)
    # Real gap found via independent review: `agreement_ratio` alone can't
    # tell a reader WHY it's below the threshold — a run stopped by an
    # unrelated kill-switch/cost-cap trigger (verdict=None) looks
    # identical, at this one field, to a run that genuinely produced a
    # DIFFERENT verdict. The `results` list already carries this
    # distinction (a null verdict vs. a named one), but a reader who only
    # glances at `agreement_ratio`/`meets_recommended_threshold` could
    # misread infra noise as the system being non-deterministic — so
    # surface the count explicitly instead of making them cross-reference
    # `results` by hand every time.
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
    }
    summary_path = Path(args.storage_dir) / f"{base_execution_id}_retest_summary.json"
    # Real gap found via this feature's own test suite: if EVERY run gets
    # BLOCKED before ever reaching EvidenceHarness construction (e.g. all
    # 3 runs hit the same planning-time cost cap), nothing ever creates
    # --storage-dir at all (EvidenceHarness.__init__ is what normally
    # does that, scoped to storage_dir/execution_id) — writing the
    # summary there would otherwise crash with a raw FileNotFoundError.
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n-> Tỷ lệ cùng verdict: {agree_count}/{len(results)} ({ratio:.0%}) — verdict phổ biến nhất: "
          f"{most_common_verdict or '(không lần nào có verdict)'}")
    if no_verdict_count:
        print(
            f"-> LƯU Ý: {no_verdict_count}/{len(results)} lần KHÔNG có verdict nào (dừng giữa chừng do "
            "kill-switch/cost-cap hoặc lỗi hạ tầng khác) — tỷ lệ trên có thể phản ánh sự cố hạ tầng, "
            "không hẳn là hệ thống thiếu tất định. Xem 'results' để biết chính xác lần nào."
        )
    print(f"-> Ngưỡng đề xuất SPEC §8.1 (>= 2/3): {'ĐẠT' if meets_threshold else 'CHƯA ĐẠT — phải ghi vào Limitations'}")
    print(f"-> retest_id: {summary['retest_id']} — lưu tóm tắt tại: {summary_path}")

    if args.format == "json":
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


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
    hypothesize_parser.add_argument(
        "--target-revision-id",
        help="target_revision_id HIỆN TẠI của target — bắt buộc nếu có --target-id. Context Store chỉ "
        "trả về verified/unverified context đã ghi cho ĐÚNG revision này; context của revision khác "
        "coi như không có (SPEC §4.6 staleness — tránh dùng nhầm kết luận cũ sau khi target đổi code). "
        "PHẢI là 1 định danh bất biến, content-addressed (vd git SHA) — 1 nhãn có thể bị đổi ý nghĩa "
        "theo thời gian (tag bị move, số build tái sử dụng) sẽ vô hiệu hoá cơ chế chống stale này.",
    )
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
    plan_parser.add_argument(
        "--target-id",
        help="target_id dự kiến sẽ execute lên — tuỳ chọn, chỉ dùng để CẢNH BÁO (không chặn) nếu khác "
        "với target_id lúc hypothesis này được sinh ra qua `hypothesize --target-id`.",
    )
    plan_parser.add_argument(
        "--target-revision-id",
        help="revision dự kiến sẽ execute lên — tuỳ chọn, dùng cùng --target-id để CẢNH BÁO nếu khác "
        "với revision lúc hypothesis này được sinh ra (SPEC §4.6 staleness — 1 tầng cao hơn "
        "verified_observations, không chặn vì retest lại 1 hypothesis cũ trên revision mới là quy "
        "trình hợp lệ, chỉ cần biết để cân nhắc, không cần chặn).",
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

    def _add_execute_common_args(parser: argparse.ArgumentParser) -> None:
        # Shared by `execute` and `retest` — a retest run needs the exact
        # same inputs execute does, just repeated N times with fresh
        # execution_ids (see retest_parser below).
        parser.add_argument(
            "--hypothesis-id", required=True, help="hypothesis_id đã lưu trong Context Store (từ `hypothesize`)"
        )
        parser.add_argument(
            "--plan-file",
            help="Dùng lại ĐÚNG plan đã `secweave plan --format json > file` lập và duyệt trước đó, thay "
            "vì gọi LLM lập plan MỚI (LLM không xác định — 2 lần gọi có thể ra 2 plan khác nhau cho cùng "
            "1 hypothesis). Không truyền cờ này thì vẫn lập plan mới như trước, tiện cho test nhanh 1 "
            "bước nhưng KHÔNG đảm bảo thực thi đúng plan đã xem qua `secweave plan`. Khớp SPEC §5.1: "
            "'Plan & dry-run' phải feed thẳng plan sang 'Execute', không lập lại giữa chừng.",
        )
        parser.add_argument(
            "--allowed-action",
            action="append",
            help='Giống hệt `plan --allowed-action` — 1 entry allowlist, dạng "METHOD https://host/path/'
            '{param} [params:key1,key2=regex]", lặp lại flag để cấp nhiều entry.',
        )
        parser.add_argument(
            "--cap",
            type=int,
            default=10,
            help="Cap số hành động — dùng CHUNG cho cả cost-check lúc lập plan lẫn CostService lúc thực "
            "thi thật (mặc định: %(default)s)",
        )
        parser.add_argument("--target-id", required=True, help="target_id ghi vào evidence")
        parser.add_argument(
            "--target-revision-id",
            required=True,
            help="target_revision_id ghi vào evidence — PHẢI là 1 định danh bất biến, content-addressed "
            "(vd git SHA), không được rỗng (SPEC §4.6 staleness dựa vào giả định này để lọc context).",
        )
        parser.add_argument(
            "--execution-id", help="Định danh execution (mặc định: tự sinh mới mỗi lần chạy)"
        )
        parser.add_argument(
            "--storage-dir",
            default=DEFAULT_EVIDENCE_STORAGE_DIR,
            help="Thư mục lưu evidence + kill-switch/cost audit log (mặc định: %(default)s)",
        )
        parser.add_argument(
            "--identity",
            default="anonymous",
            help="Identity mặc định — dùng cho mọi role KHÔNG có --role-identity riêng (mặc định: "
            "%(default)s)",
        )
        parser.add_argument(
            "--role-identity",
            action="append",
            help='1 entry ánh xạ role -> identity, dạng "ROLE=LABEL" (vd "positive_control=owner"). Lặp '
            "lại flag để khai nhiều role. ROLE phải là 1 trong main/positive_control/denied_control/setup "
            "(ActionSpec.role, do Exploit Agent gắn khi lập plan cho 1 kịch bản 3-role) — LABEL chỉ là "
            "tên identity, không phải credential thật (Exploit Agent không tự lấy credential, chỉ tự gắn "
            "role). Role không có entry riêng ở đây dùng --identity mặc định.",
        )
        parser.add_argument(
            "--identity-logins",
            help="Đường dẫn file JSON: {label: {method, target, parameters, description?, token_json_path?, "
            "token_header?, token_prefix?}} — mỗi label sẽ được harness.login() thật trước khi plan chạy, "
            "nếu label đó được --identity hoặc --role-identity tham chiếu tới. Label không có entry trong "
            "file này chạy KHÔNG đăng nhập (client mới, chưa có session) — vẫn là 1 identity hợp lệ (vd "
            "denied_control ẩn danh). Bỏ trống token_json_path cho target dùng session kiểu cookie.",
        )
        parser.add_argument(
            "--sensitive-param",
            action="append",
            help="Tên field trong ActionSpec.parameters (hoặc query string cùng tên trong target) mà GIÁ "
            "TRỊ không được ghi ra đĩa trong transcript bằng chứng — lặp lại flag để khai nhiều field "
            "(vd --sensitive-param password --sensitive-param api_key). Chỉ ảnh hưởng bản ghi lưu lại, "
            "không ảnh hưởng request thật đã gửi. Không truyền = không field nào được coi là nhạy cảm "
            "ngoài header Authorization/Cookie/Set-Cookie (luôn redact sẵn).",
        )
        _add_llm_mode_arg(parser)
        _add_context_db_arg(parser)

    execute_parser = subparsers.add_parser(
        "execute",
        help="Thực thi THẬT các action đã approve của 1 plan (nối KillSwitch/CostService/"
        "EvidenceHarness) — SẼ GỬI REQUEST THẬT, chỉ chạy khi thực sự được phép trên target đó",
    )
    _add_execute_common_args(execute_parser)
    execute_parser.set_defaults(func=cmd_execute)

    retest_parser = subparsers.add_parser(
        "retest",
        help="Chạy lại CÙNG 1 plan đã đóng băng nhiều lần độc lập (SPEC §8.1: reproducibility) — đo tỷ "
        "lệ cùng verdict, KHÔNG được tự chọn lần 'đẹp nhất' để báo cáo",
    )
    _add_execute_common_args(retest_parser)
    retest_parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Số lần chạy lại độc lập (mặc định: %(default)s — SPEC §8.1 đề xuất tối thiểu 3, ngưỡng "
        "đạt yêu cầu đề xuất là >= 2/3 lần cùng verdict). Mỗi lần dùng 1 execution_id riêng, KHÔNG dùng "
        "chung kill-switch/cost — reset hoàn toàn giữa các lần để đo đúng khả năng lặp lại của HỆ "
        "THỐNG, không phải cộng dồn ngân sách qua nhiều lần.",
    )
    _add_format_arg(retest_parser)
    retest_parser.set_defaults(func=cmd_retest)

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
