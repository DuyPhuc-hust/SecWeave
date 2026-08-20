"""Helpers shared by 2 or more `secweave` subcommands. Anything used by
exactly one command lives in that command's own module under
`cli/commands/` instead — this file is deliberately not a catch-all."""

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Optional, Type, TypeVar

from pydantic import ValidationError

from context_store.store import SecurityContextStore
from hypothesis_engine.signal_normalizer.orchestrator import SignalNormalizer
from shared.id_generator import generate_id
from shared.models.entities import Authorization, AuthorizationLayer
from shared.models.hypothesis import Hypothesis, HypothesisProvenance
from shared.models.kill_switch import ExecutionStatus
from shared.models.observation import NormalizedObservation
from shared.models.signal import NormalizedSignal, SignalCoverage
from verdict_oracle.oracle import decide


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
    what was recorded when this hypothesis was generated. A warning rather
    than a CliError deliberately: re-testing an OLD hypothesis against a
    NEWER revision on purpose (e.g. confirming a fix landed) is a
    legitimate workflow WEEKLY_PLAN W7 itself describes — this must not
    block it, only make the operator aware. Only compared when BOTH sides
    are known (a NULL/None on either side means nothing to compare
    against, not a mismatch).

    An empty string (`""`) is rejected outright rather than silently
    treated as "nothing to compare" — it's just as falsy as `None` in the
    comparison below, so `--target-id ""` (e.g. an unset shell variable
    interpolated into a script) would otherwise skip the cross-check with
    no warning and no error, indistinguishable from the flag never being
    passed.
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

    _print_hypothesis_staleness_warning(record, hypothesis_id, current_target_id, current_revision)

    try:
        return _load_stored_hypothesis(record)
    except ValueError as exc:
        raise CliError(str(exc)) from exc


def _print_hypothesis_staleness_warning(
    record: dict,
    hypothesis_id: str,
    current_target_id: Optional[str],
    current_revision: Optional[str],
) -> None:
    """The comparison itself, factored out so both
    `_load_hypothesis_from_context_store` (the non---plan-file path) and
    `_warn_if_hypothesis_stale` (the --plan-file path, see below) print the
    exact same warning text instead of 2 copies drifting apart."""
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


def _warn_if_hypothesis_stale(
    context_store: SecurityContextStore,
    hypothesis_id: str,
    current_target_id: Optional[str],
    current_revision: Optional[str],
) -> None:
    """Best-effort twin of `_load_hypothesis_from_context_store`'s staleness
    cross-check, for the `--plan-file` path of `execute`/`retest` — that
    path never reconstructs a Hypothesis (the frozen plan file already has
    the ActionPlan), so it needs this separate check to warn at all, even
    though `--plan-file` is the documented, RECOMMENDED way to run
    `execute`. Unlike
    `_load_hypothesis_from_context_store`, a missing hypothesis_id or a
    Context Store error here is NOT an error — `--plan-file` has never
    required the hypothesis to still exist in this context-db (it may
    have been generated in a different db, or the db may have been
    rotated), so this only warns when there is something concrete to warn
    about, silently doing nothing otherwise. Always closes `context_store`.
    """
    if current_target_id == "":
        raise CliError("target_id truyền vào để đối chiếu không được là chuỗi rỗng — bỏ hẳn cờ nếu không cần.")
    if current_revision == "":
        raise CliError("revision truyền vào để đối chiếu không được là chuỗi rỗng — bỏ hẳn cờ nếu không cần.")
    try:
        record = context_store.get_hypothesis(hypothesis_id)
    except RuntimeError:
        return
    finally:
        context_store.close()
    if record is not None:
        _print_hypothesis_staleness_warning(record, hypothesis_id, current_target_id, current_revision)


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
        observation_dicts = [
            json.loads(line) for line in observations_path.read_text(encoding="utf-8").splitlines() if line
        ]
    except (json.JSONDecodeError, OSError) as exc:
        raise CliError(f"không đọc được artifact của execution '{execution_id}': {exc}") from exc
    # Same class of gap as assemble-package's own read of this file — see
    # its comment for why an isinstance guard is needed before Model(**o).
    if not all(isinstance(o, dict) for o in observation_dicts):
        raise CliError(f"'{observations_path}' có dòng không phải JSON object — file này có bị sửa tay không?")
    try:
        observations = [NormalizedObservation(**o) for o in observation_dicts]
        execution_status = ExecutionStatus(json.loads(status_path.read_text(encoding="utf-8"))["execution_status"])
    except (json.JSONDecodeError, ValidationError, ValueError, OSError) as exc:
        raise CliError(f"không đọc được artifact của execution '{execution_id}': {exc}") from exc
    if not observations:
        return None
    return decide(observations, execution_status=execution_status).verdict.value
