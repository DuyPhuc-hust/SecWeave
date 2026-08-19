import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field, ValidationError

from cli.common import (
    CliError,
    _build_llm_client,
    _build_local_test_authorization,
    _load_hypothesis_from_context_store,
    _open_context_store,
    _parse_enum_arg,
)
from evidence_harness.harness import EvidenceHarness
from exploit_agent.agent import ExploitAgent
from shared.cost import CostService
from shared.id_generator import generate_id
from shared.kill_switch import KillSwitch
from shared.models.action import ActionPlanResult, ActionPlanStatus, ActionSpec, ActionType
from shared.models.kill_switch import ExecutionStatus
from shared.models.observation import BLIND_MARKER_PLACEHOLDER, NormalizedObservation, ObservationRole
from shared.policy import is_allowed
from verdict_oracle.oracle import decide


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
    except OSError as exc:
        raise CliError(f"không đọc được --identity-logins file '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CliError(f"--identity-logins file '{path}' không phải JSON hợp lệ: {exc}") from exc

    if not isinstance(raw, dict):
        raise CliError(f"--identity-logins file '{path}' phải là 1 JSON object (label -> cấu hình login).")
    # Real gap found via independent review: only the OUTER shape (dict)
    # was checked — a value that isn't itself a JSON object (e.g.
    # {"owner": "typo'd string"}) reached `_IdentityLoginSpec(**cfg)`
    # unguarded, raising a raw TypeError ("argument after ** must be a
    # mapping, not str") instead of the clean CliError every other
    # malformed-shape case in this file now produces.
    non_dict_labels = [label for label, cfg in raw.items() if not isinstance(cfg, dict)]
    if non_dict_labels:
        raise CliError(
            f"--identity-logins file '{path}': entry cho label {sorted(non_dict_labels)} phải là 1 JSON "
            "object (cấu hình login), không phải giá trị khác."
        )

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
    # Real gap found via independent review: unlike --target-revision-id
    # (enforced by Context Store's own _require_revision — every observation
    # write fails loud on empty), --target-id had NO equivalent enforcement
    # anywhere (context_store/store.py never validates it). The only place
    # that happened to reject "" was `_load_hypothesis_from_context_store`'s
    # own staleness cross-check — but that helper only runs on the non-
    # --plan-file branch below, so the (documented, RECOMMENDED) --plan-file
    # path silently accepted --target-id "" and baked it into every
    # observation/Context Store write for this run. Checked here, uniformly,
    # regardless of which branch runs.
    if not args.target_id:
        raise CliError("--target-id không được để trống.")

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
        try:
            existing_actions_raw = (
                json.loads(actions_path.read_text(encoding="utf-8")) if actions_path.exists() else []
            )
        except (json.JSONDecodeError, OSError) as exc:
            raise CliError(f"không đọc lại được '{actions_path}': {exc}") from exc
        # Real gap found via independent review: actions.json is operator-
        # editable between 2 `execute` calls reusing the same execution_id
        # (a supported pattern, see this function's own comment above) —
        # an accidental hand-edit that breaks its list-of-objects shape
        # used to crash `item["action_id"]` with a raw TypeError/KeyError
        # instead of a clean CliError, same class of gap fixed elsewhere
        # in this file for this exact artifact.
        if not isinstance(existing_actions_raw, list) or not all(
            isinstance(item, dict) and "action_id" in item for item in existing_actions_raw
        ):
            raise CliError(f"'{actions_path}' phải là 1 danh sách ActionSpec (JSON object) — file này có bị sửa tay không?")
        by_action_id = {item["action_id"]: item for item in existing_actions_raw}
        for action in new_actions:
            by_action_id[action.action_id] = action.model_dump(mode="json")
        try:
            actions_path.write_text(json.dumps(list(by_action_id.values()), indent=2), encoding="utf-8")
        except OSError as exc:
            raise CliError(f"không ghi được '{actions_path}': {type(exc).__name__}: {exc}") from exc

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
        try:
            with open(observations_log_path, "a", encoding="utf-8") as f:
                f.write(observation.model_dump_json() + "\n")
        except OSError as exc:
            # Real gap found via independent review: unlike `report`'s
            # --out write (already hardened), this append had no guard —
            # a disk-full/permission failure here crashed with a raw
            # traceback instead of a clean CliError, and — worse — the
            # observation this call is persisting had already been
            # appended to the in-memory `observations` list above, so a
            # silently-swallowed failure here would have gone on to
            # compute a verdict from evidence that was never actually
            # durable on disk. Fail loudly instead: on-disk
            # observations.jsonl is the ONLY source of truth every later
            # command (assemble-package/retest/measure) reads back.
            raise CliError(
                f"không ghi được observation vào '{observations_log_path}': {type(exc).__name__}: {exc}"
            ) from exc

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
    execution_status_path = harness_storage_dir / "execution_status.json"
    try:
        execution_status_path.write_text(
            json.dumps({"execution_status": execution_status.value}), encoding="utf-8"
        )
    except OSError as exc:
        # Real gap found via independent review: unguarded, unlike `report`
        # --out's write — a disk-full/permission failure here happens
        # AFTER every real HTTP request of this run already completed, so
        # a raw traceback here would also swallow the verdict printout
        # below that reports what the run actually did.
        raise CliError(
            f"không ghi được '{execution_status_path}': {type(exc).__name__}: {exc}"
        ) from exc

    if observations:
        result = decide(observations, execution_status=execution_status)
        print(f"-> Verdict: {result.verdict.value}")
        print(f"   {result.reason}")

    return 1 if stopped_reason else 0
