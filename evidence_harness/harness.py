"""Evidence Harness — SPEC §4.3. Executes one already-approved ActionSpec for
real via httpx, captures the full raw request/response transcript immutably,
hashes it, and derives a NormalizedObservation (shared/models/observation.py)
for the Oracle to read. "Không diễn giải, không kết luận" (SPEC §4.3): this
module only classifies mechanically (status code -> access_result), it never
states a verdict.

Scope of this increment — what this does NOT do yet:
- Only the HTTP_TRANSACTION channel (SPEC §4.3.2's other 4 channels have no
  producer yet — see shared/models/observation.py's module docstring).
- Blind marker (§4.3.4) is PARTIALLY here: generate_marker() generates this
  run's marker and persists it to a seed manifest (only this process and,
  once built, Verdict Oracle ever read that file — never Exploit Agent/any
  LLM, since ActionSpec has no field for it and nothing wires it into a
  prompt). capture(..., marker=...) does the actual response/request check.
  What's still scenario-specific and NOT provided here: actually planting
  the marker into real bait data (what resource, what field) — callers build
  their own ActionSpec for that (from trusted setup code, never from Exploit
  Agent's plan) and pass role=ObservationRole.SETUP to capture() it as
  evidence without it being mistaken for predicate evidence.
- Does NOT implement the full redaction policy (§4.3.5) — that field catalog
  is explicitly "chốt tại Gate 3 cùng owner", which hasn't happened (still
  Chặng 1). This module applies only a minimal hardcoded floor — never
  writes Authorization/Cookie/Set-Cookie header VALUES to disk — as a safety
  net, not a substitute for the real owner-defined policy.
- Does NOT build a package-level manifest (§4.3.3) listing every artifact's
  hash — that spans a whole run's observations, not a single capture().
- The seed manifest file has no OS-level access control (SPEC's "chỉ
  Harness+Oracle đọc được" is enforced architecturally — no code path wires
  it into an LLM-facing prompt — not via filesystem permissions).

Identity/session handling: each identity gets its own httpx.Client/cookie
jar (see EvidenceHarness's own docstring), and login() establishes a
session generically — it just executes
a caller-supplied ActionSpec describing THIS target's login shape through
that identity's client, no target-specific code anywhere in this module.
Still NOT solved: WHERE a real login_action's credentials (username/
password, or a pre-existing token) come from for an actual Gate 2 identity —
same "gates assumed approved" situation as everything else in Chặng 1, the
caller/operator supplies them, this module doesn't source or store them
beyond one run's in-memory cookie jars.

Kill-switch integration (SPEC §6.3/§5.3, see shared/kill_switch.py for the
full design): capture() optionally takes a KillSwitch and checks
`is_stopped` before sending any real request, raising ExecutionStoppedError
instead of executing it once stopped. EvidenceHarness does not own or
create the KillSwitch — a caller constructs one and shares the SAME instance
across everything for one execution (capture() calls, and the real Cost
Service below), same as it shares one execution_id.

Cost Service integration (SPEC P6/§6.4 control #9, weekly plan Tuần 6, see
shared/cost.py for the full design): capture() optionally takes a
CostService and records each real ATTEMPT against it before sending
anything. The moment the next action would exceed the configured cap,
capture() refuses to send it (raising CostCapExceededError) AND — if a
KillSwitch is also wired in — automatically stops the execution
(source=AUTOMATIC_THRESHOLD, automatic_threshold_reason=
ACTION_COUNT_EXCEEDED), same "gates assumed approved, operator-supplied cap"
situation as everything else in Chặng 1: this module doesn't decide what
the cap should be, only enforces whatever value a caller configured.
EvidenceHarness does not own or create the CostService either, same
sharing convention as KillSwitch.
"""

import base64
import copy
import hashlib
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from context_store.store import SecurityContextStore
from shared.cost import CostCapExceededError, CostService
from shared.id_generator import generate_id
from shared.kill_switch import AutomaticThresholdReason, ExecutionStoppedError, KillSwitch, StopSource
from shared.models.action import ActionSpec
from shared.models.observation import (
    AccessResult,
    EvidenceChannel,
    NormalizedObservation,
    ObservationRole,
)

# Minimal safety floor, not the real redaction catalog (see module docstring).
# Extended per-instance by login() when a caller uses a custom token_header —
# a custom header name (e.g. "X-Access-Token") must redact just as much as
# the standard "Authorization" does, on every subsequent request, not just
# the login itself.
_BASE_REDACTED_HEADERS = {"authorization", "cookie", "set-cookie"}
_REDACTED_PLACEHOLDER = "<redacted>"

# Methods conventionally read via query string rather than a body. Not part
# of SPEC — ActionSpec.parameters doesn't say whether it's a query string or
# a body (a gap, like the ActionSpec/role one flagged in observation.py), so
# this is a documented, simple heuristic rather than a guess made silently.
_QUERY_STRING_METHODS = {"GET", "HEAD", "DELETE"}

# Hard cap on how much of a response body capture() will read into memory
# and store per action — an unbounded response (from a misbehaving or
# adversarial target) has no other ceiling, risking an OOM crash on a
# single capture() call. 10 MiB is generous for the JSON/HTML/text bodies
# this project's real targets actually return.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


def _redact_headers(headers: Dict[str, str], sensitive_names: Set[str]) -> Dict[str, str]:
    return {
        key: (_REDACTED_PLACEHOLDER if key.lower() in sensitive_names else value)
        for key, value in headers.items()
    }


def _redact_body(body: Any, sensitive_keys: Optional[Set[str]]) -> Any:
    # Only redacts a top-level dict's named keys — deliberately not
    # recursive/heuristic (e.g. scanning for anything that "looks like" a
    # password). ActionSpec.parameters shape is entirely target-specific, so
    # guessing which nested fields are secrets would be exactly the kind of
    # silent, incomplete denylist this project avoids elsewhere (see
    # shared/policy.py's key-based, caller-declared params: allowlist for the
    # same reasoning). Callers that need more must say so explicitly.
    if not sensitive_keys or not isinstance(body, dict):
        return body
    return {key: (_REDACTED_PLACEHOLDER if key in sensitive_keys else value) for key, value in body.items()}


def _strip_userinfo(netloc: str) -> str:
    """Drops a `user:pass@` prefix from a URL's netloc, unconditionally —
    unlike query-key redaction (opt-in, via caller-declared sensitive_keys),
    userinfo is ALWAYS credential-shaped when present (HTTP Basic Auth
    embedded directly in the URL), so there's no legitimate case where it
    should be persisted, and no opt-out.
    """
    return netloc.rsplit("@", 1)[-1] if "@" in netloc else netloc


def _redact_url_query(url: str, sensitive_keys: Optional[Set[str]]) -> str:
    """Redacts the VALUES of any query-string parameter whose key is in
    `sensitive_keys`, directly in a URL string — `action.target` can carry
    its OWN query string, independent of `action.parameters`, and a secret
    embedded there (e.g. a password-reset token, an API key) needs the
    same redaction path as body/params. Only rewrites the query component;
    scheme/host/path/fragment untouched. Policy Service already denies any
    action whose `target` carries its own query string (shared/policy.py)
    — this is defense in depth for any caller that reaches capture()
    directly, not the primary control.
    """
    parts = urlsplit(url)
    userinfo_free_netloc = _strip_userinfo(parts.netloc)
    if userinfo_free_netloc != parts.netloc:
        # Userinfo present — always rewritten (see _strip_userinfo), even
        # if no query-key redaction is otherwise needed below.
        url = urlunsplit((parts.scheme, userinfo_free_netloc, parts.path, parts.query, parts.fragment))
        parts = urlsplit(url)
    if not sensitive_keys:
        return url
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not any(key in sensitive_keys for key, _ in pairs):
        # Re-encoding via urlencode(parse_qsl(...)) is not a byte-exact
        # identity transform (e.g. a bare flag gains "=value", "%20"
        # becomes "+", an unescaped "/" becomes "%2F") — decodes to the
        # same logical values but drifts from what was literally sent.
        # Returning the URL byte-for-byte untouched when nothing actually
        # needs redacting avoids that drift; some cosmetic re-encoding of
        # the OTHER params is accepted only once a key genuinely must hide.
        return url
    redacted_pairs = [
        (key, _REDACTED_PLACEHOLDER if key in sensitive_keys else value) for key, value in pairs
    ]
    new_query = urlencode(redacted_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _charset_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """Extracts a declared charset from a Content-Type header value, e.g.
    "text/html; charset=windows-1252" -> "windows-1252", or None if absent
    — fed into _decode_response_body (see its docstring for why this
    matters). Reads the header directly rather than relying on httpx's
    internal encoding-detection state, since this module reads the body
    itself via manual chunked iteration (for the size cap) rather than
    through httpx's normal buffered-read path.
    """
    content_type = headers.get("content-type") or headers.get("Content-Type")
    if not content_type:
        return None
    for part in content_type.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            return value.strip('"').strip("'")
    return None


def _decode_response_body(raw_bytes: bytes, declared_charset: Optional[str] = None) -> Tuple[str, str]:
    """Returns (text, encoding_label) for a raw response body. Prefers
    literal UTF-8 (encoding_label="utf-8") so the common JSON/HTML/text
    case stays human-readable in the stored artifact; falls back to
    base64 (encoding_label="base64") for anything that isn't valid UTF-8,
    so the stored bytes are always a LOSSLESS, byte-exact representation
    of what was actually received — unlike httpx's own `.text` property,
    which silently substitutes U+FFFD for invalid bytes with no record
    that this happened, undermining the Oracle's hash re-verification
    (which only proves the artifact hasn't changed SINCE capture, not that
    capture faithfully recorded the real wire bytes to begin with).

    `declared_charset` (from `_charset_from_headers`), if given and not
    already "utf-8", is tried FIRST — a body genuinely encoded as e.g.
    windows-1252 that HAPPENS to also be valid (but wrong) UTF-8 must not
    be silently misdecoded just because UTF-8 was tried unconditionally.
    """
    if declared_charset and declared_charset.lower() not in ("utf-8", "utf8"):
        try:
            return raw_bytes.decode(declared_charset), declared_charset.lower()
        except (LookupError, UnicodeDecodeError):
            pass  # unknown/wrong-declared charset — fall through to UTF-8/base64 below
    try:
        return raw_bytes.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return base64.b64encode(raw_bytes).decode("ascii"), "base64"


def _redact_json_path(data: Any, path_parts: List[str]) -> Any:
    """Returns a deep copy of `data` with the value at `path_parts` replaced
    by the redaction placeholder — used to scrub a just-extracted auth token
    out of a login response body before it's written to disk. Only handles
    the exact path a caller already proved exists (login() calls this right
    after successfully extracting the token from that same path).
    """
    data = copy.deepcopy(data)
    node = data
    for part in path_parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    last = path_parts[-1]
    if isinstance(node, list):
        node[int(last)] = _REDACTED_PLACEHOLDER
    else:
        node[last] = _REDACTED_PLACEHOLDER
    return data


def _classify_access_result(status_code: Optional[int]) -> AccessResult:
    """Mechanical bucketing only (see shared/models/observation.py's
    AccessResult docstring) — not a security judgment. 401/403 are the only
    codes with an unambiguous "denied" meaning; everything else (404, 3xx,
    5xx, or no response at all) could mean several different things, so it
    falls to AMBIGUOUS rather than being force-fit.
    """
    if status_code is None:
        return AccessResult.AMBIGUOUS
    if 200 <= status_code < 300:
        return AccessResult.GRANTED
    if status_code in (401, 403):
        return AccessResult.DENIED
    return AccessResult.AMBIGUOUS


def _contains_marker(text: Optional[str], marker: Optional[str]) -> Optional[bool]:
    # None (not False) when no marker is in play for this scenario — matches
    # NormalizedObservation's own None-vs-False distinction for these fields.
    if marker is None:
        return None
    if not text:
        return False
    # Case-insensitive — the marker is always lowercase hex
    # (secrets.token_hex), but a target that reflects it back with
    # different casing (a case-folding DB collation, an upper-casing
    # display layer) must not turn a real leak into a false negative over
    # a casing distinction that carries no real signal either way.
    return marker.lower() in text.lower()


class EvidenceHarness:
    """One instance = one execution context. execution_id/target/revision are
    fixed for the whole run (SPEC §4.3.2 ties them to the execution, not to a
    single action), so they're set once here. identity is NOT fixed per
    instance — it's per capture() call (see that method), because a single
    run needs to act as MULTIPLE identities (e.g. positive_control as the
    resource's real owner, denied_control as someone else) for those
    predicate groups to test anything real.

    Each identity gets its OWN httpx.Client, i.e. its own cookie jar —
    logging in as one identity (see login()) never affects another's
    session. This leans on httpx's own cookie-jar handling (Set-Cookie on a
    response is automatically stored and replayed on later requests through
    the SAME client) instead of hand-rolling cookie parsing/attachment.
    """

    def __init__(
        self,
        execution_id: str,
        target_id: str,
        target_revision_id: str,
        storage_dir: str,
        http_client: Optional[httpx.Client] = None,
        http_client_factory: Optional[Callable[[], httpx.Client]] = None,
        kill_switch: Optional[KillSwitch] = None,
        cost_service: Optional[CostService] = None,
        context_store: Optional[SecurityContextStore] = None,
    ) -> None:
        # Validated here, at construction, rather than left to surface deep
        # inside capture()'s best-effort Context Store write (which only
        # catches RuntimeError — an empty target_revision_id makes
        # context_store/store.py's _require_revision raise a plain
        # ValueError instead, escaping uncaught). Every caller of this
        # class gets the same load-bearing check, not just callers that
        # happen to validate this themselves first.
        if not target_id:
            raise ValueError("EvidenceHarness: target_id không được để trống.")
        if not target_revision_id:
            raise ValueError("EvidenceHarness: target_revision_id không được để trống.")
        self._execution_id = execution_id
        self._target_id = target_id
        self._target_revision_id = target_revision_id
        self._storage_dir = Path(storage_dir) / execution_id
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._seed_manifest_path = self._storage_dir / "seed_manifest.json"
        # Not owned/created here — see this module's docstring and
        # shared/kill_switch.py. None means no kill-switch is wired in at
        # all (capture() never refuses on that basis), not "never stopped".
        self._kill_switch = kill_switch
        # Same "not owned/created here" convention — see this module's
        # docstring and shared/cost.py. None means no runtime cost cap is
        # enforced at all (capture() never refuses on that basis).
        self._cost_service = cost_service
        # SPEC §4.6's write-path diagram: "Evidence Harness -- ghi quan sát,
        # trạng thái = unverified --> Context Store." Same "not owned/
        # created here" convention as kill_switch/cost_service — None means
        # capture() simply doesn't record anything to the Context Store
        # (no error, just no bookkeeping), matching how the other two
        # optional collaborators degrade when absent.
        self._context_store = context_store
        # `http_client`: one SHARED instance/jar for EVERY identity — ONLY
        # for tests that genuinely don't care about identity isolation
        # (testing something else entirely, e.g. a single-identity capture()
        # scenario). Using this for anything else silently defeats per-
        # identity cookie/token isolation — login("alice", ...) and
        # login("bob", ...) would clobber the SAME jar/headers, since
        # _client_for() ignores the identity argument on this path. A real
        # (or realistic multi-identity test) scenario MUST use
        # `http_client_factory` instead. `http_client_factory`: called once
        # per NEW identity to build that identity's own isolated client —
        # lets tests use httpx.MockTransport while still exercising real
        # isolation, instead of only being reachable via a real network
        # client. Neither given -> real httpx.Client() per identity
        # (production default, also correctly isolated).
        self._injected_client = http_client
        self._client_factory = http_client_factory or httpx.Client
        self._owns_clients = http_client is None
        self._clients: Dict[str, httpx.Client] = {}
        # Starts at the hardcoded floor, grows as login() is used with a
        # custom token_header — see _redact_headers's call sites below.
        self._sensitive_header_names: Set[str] = set(_BASE_REDACTED_HEADERS)
        # Tracks which header name currently holds each identity's token, so
        # re-login()-ing with a DIFFERENT token_header can remove the stale
        # one instead of leaving both attached forever.
        self._token_header_by_identity: Dict[str, str] = {}
        # Tracked so capture() can raise a clear, own RuntimeError once this
        # instance is closed, rather than either crashing on httpx's own
        # "client has been closed" error (not an httpx.HTTPError/InvalidURL
        # subclass) or silently building a fresh client that drops the
        # identity's prior session state.
        self._closed = False

    def _client_for(self, identity: str) -> httpx.Client:
        if self._injected_client is not None:
            return self._injected_client
        if identity not in self._clients:
            self._clients[identity] = self._client_factory()
        return self._clients[identity]

    def generate_marker(self) -> str:
        """SPEC §4.3.4 — generates this run's blind marker and persists it to
        a seed manifest file scoped to this execution_id. A run has exactly
        ONE marker: if a manifest already exists (this process called it
        before, or an earlier process run for the same execution_id did),
        that value is returned unchanged rather than rotating it — seeding
        one marker into bait data and then checking against a *different*
        regenerated one would make every check silently fail.

        The returned string must never be handed to Exploit Agent/any LLM
        context — SPEC's own table names ONLY Harness and Oracle as
        legitimate readers. Nothing in this codebase currently wires this
        value into a prompt (ActionSpec has no field for it), and it should
        stay that way; only trusted setup/orchestration code should call
        this, never code that builds LLM input.
        """
        existing = self._read_seed_manifest()
        if existing is not None:
            return existing["marker"]

        marker = secrets.token_hex(16)
        manifest = {
            "execution_id": self._execution_id,
            "marker": marker,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        raw = json.dumps(manifest, indent=2, sort_keys=True)

        # Write the FULL content to a temp file first, then atomically claim
        # the real path via a hard link — os.link() only ever points the
        # destination at an already-fully-written file, so a racing reader
        # (a second process constructing the same execution_id) can never
        # observe a partial manifest, unlike open(path, "x") + write() as 2
        # separate steps.
        fd, tmp_path = tempfile.mkstemp(dir=self._storage_dir, prefix="seed_manifest.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(raw)
            try:
                os.link(tmp_path, self._seed_manifest_path)
                return marker
            except FileExistsError:
                return self._read_seed_manifest()["marker"]
        finally:
            os.unlink(tmp_path)

    def _read_seed_manifest(self) -> Optional[Dict[str, Any]]:
        if not self._seed_manifest_path.exists():
            return None
        return json.loads(self._seed_manifest_path.read_text(encoding="utf-8"))

    def capture(
        self,
        action: ActionSpec,
        role: ObservationRole,
        marker: Optional[str] = None,
        identity: str = "anonymous",
        sensitive_body_keys: Optional[Set[str]] = None,
    ) -> NormalizedObservation:
        """Executes `action` for real, writes the raw transcript to disk
        immutably, and returns the derived NormalizedObservation. Never
        raises on an HTTP-level failure (timeout, connection refused, etc.)
        — a failed attempt is still evidence (SPEC P2: "bằng chứng trước,
        phát biểu sau"), so it's captured as raw_evidence with no response,
        not silently dropped.

        `identity` selects which identity's client (and therefore cookie
        jar / session) sends this request — default "anonymous" for actions
        that don't need one (no prior login(), so no cookies are attached;
        this is not a magic string with special handling, just an identity
        name nobody has logged in as). See login() to establish a session
        for a real identity first.

        `sensitive_body_keys`: top-level keys in action.parameters whose
        VALUES must never be written to disk (e.g. {"password"} for a login
        action) — see _redact_body's docstring for why this is caller-
        declared rather than guessed. ALSO covers a same-named query-string
        parameter embedded directly in `action.target`'s own URL (see
        _redact_url_query's docstring). Only affects the STORED transcript,
        never the real request actually sent.

        The stored `request.url` is the REAL, resolved URL httpx actually
        sent (`str(request.url)`), not `action.target` verbatim — for
        GET/HEAD/DELETE, httpx's `params=` REPLACES (not merges) a URL's
        own query string, so if `action.target` carried its own query
        string AND `action.parameters` was non-empty, recording
        `action.target` as "what was sent" would be a fidelity mismatch
        against the actual outgoing request. (Policy Service already
        denies any action.target with its own query string in the
        properly-gated pipeline — this fixes capture()'s OWN behavior as
        defense in depth, not reliance on the caller having gated first.)

        The response body is read with a hard size cap (`_MAX_RESPONSE_BYTES`)
        to bound memory use per call, and decoded as UTF-8 when possible or
        base64 (labeled via `body_encoding` in the stored artifact) when
        not — see `_decode_response_body`'s docstring for why.

        Raises ExecutionStoppedError instead of sending anything if this
        instance was given a KillSwitch and it is currently STOPPED (SPEC:
        "Agent hoặc model không có quyền từ chối lệnh dừng") — see
        shared/kill_switch.py for the full design and its stated limits
        (this is a check-before-send guard, not a mid-flight abort).

        Raises CostCapExceededError instead of sending anything if this
        instance was given a CostService and this action would be the one
        to push the executed-action count past its configured cap — also
        automatically calls kill_switch.stop(source=AUTOMATIC_THRESHOLD) if
        a KillSwitch was ALSO given, so a cap breach doesn't just refuse
        this one action but halts the whole execution (SPEC §6.4 control
        #9: "không vượt hard cost cap"). See shared/cost.py for the full
        design. The cost check deliberately runs only AFTER
        client.build_request() has already succeeded — consuming a cost
        slot any EARLIER would let a harness-internal failure unrelated to
        the target (a broken http_client_factory, a non-serializable
        action.parameters) consume real budget for an action that never
        had a chance to reach the wire.

        Raises RuntimeError if this harness instance has already been
        close()'d — see `self._closed`'s own comment in __init__.
        """
        if self._closed:
            raise RuntimeError(
                f"EvidenceHarness cho execution '{self._execution_id}' đã close() — không thể "
                "capture() thêm trên instance này. Tạo instance mới nếu cần tiếp tục thu bằng chứng."
            )
        if self._kill_switch is not None:
            # refresh() before checking — `is_stopped` only reads this
            # instance's own in-memory `_status`, so a stop() written by a
            # SEPARATE KillSwitch instance (e.g. a `secweave kill` CLI
            # invocation in a different process) would otherwise be
            # invisible here no matter how many actions ran afterward.
            self._kill_switch.refresh()
            if self._kill_switch.is_stopped:
                raise ExecutionStoppedError(
                    f"Execution '{self._execution_id}' đã STOPPED — capture() từ chối gửi request "
                    f"thật cho action '{action.action_id}'. Xem kill_switch_audit_log.jsonl của "
                    "execution này để biết ai/khi nào/vì sao đã dừng."
                )
        observation_id = generate_id("obs")
        captured_at = datetime.now(timezone.utc)
        client = self._client_for(identity)

        request_body: Optional[Any] = None
        params: Optional[Dict[str, Any]] = None
        if action.method.upper() in _QUERY_STRING_METHODS:
            params = action.parameters or None
        else:
            request_body = action.parameters or None

        status_code: Optional[int] = None
        response_text: Optional[str] = None
        body_encoding = "utf-8"
        response_truncated = False
        response_headers_raw: Dict[str, str] = {}
        received_response = False
        request_headers: Dict[str, str] = {}
        sent_url = action.target  # overwritten below once build_request() resolves the real URL
        try:
            # build_request() (not the one-shot request()) so the actual
            # resolved headers — including any cookies httpx's jar attaches
            # for this identity's client — can be captured into the raw
            # transcript below, redacted, before sending. Confirmed live:
            # httpx merges the client's cookie jar into these headers at
            # build time already, not just at send time.
            request = client.build_request(
                method=action.method,
                url=action.target,
                params=params,
                json=request_body,
            )
            sent_url = str(request.url)
            request_headers = _redact_headers(dict(request.headers), self._sensitive_header_names)

            if self._cost_service is not None:
                decision = self._cost_service.record_action(action.action_id)
                if not decision.allowed:
                    if self._kill_switch is not None:
                        self._kill_switch.stop(
                            source=StopSource.AUTOMATIC_THRESHOLD,
                            automatic_threshold_reason=AutomaticThresholdReason.ACTION_COUNT_EXCEEDED,
                            reason=decision.reason,
                        )
                    raise CostCapExceededError(
                        f"Execution '{self._execution_id}': {decision.reason} Không gửi request "
                        f"thật cho action '{action.action_id}'."
                    )

            # stream=True so the body can be read in bounded chunks (size
            # cap below) instead of httpx buffering the entire body into
            # memory unconditionally before we get any say in the matter.
            response = client.send(request, stream=True)
            try:
                status_code = response.status_code
                response_headers_raw = dict(response.headers)
                chunks: List[bytes] = []
                total_bytes = 0
                for chunk in response.iter_bytes():
                    remaining = _MAX_RESPONSE_BYTES - total_bytes
                    if len(chunk) > remaining:
                        # Keep the part of this chunk that still fits before
                        # breaking — a response delivered as one single big
                        # chunk (plausible for fast loopback targets) would
                        # otherwise lose its ENTIRE body while still being
                        # labeled merely "truncated", not empty.
                        chunks.append(chunk[:remaining])
                        response_truncated = True
                        break
                    chunks.append(chunk)
                    total_bytes += len(chunk)
            finally:
                response.close()
            response_text, body_encoding = _decode_response_body(
                b"".join(chunks), _charset_from_headers(response_headers_raw)
            )
            received_response = True
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # httpx.InvalidURL (e.g. a malformed port/host in action.target,
            # a realistic failure mode since target comes from LLM-authored
            # text) is NOT a subclass of httpx.HTTPError — verified against
            # the installed httpx version. Catching only HTTPError let this
            # exception escape uncaught, crashing capture() before any
            # artifact was written — the exact "lose evidence to a crash"
            # failure this method's own docstring promises never happens.
            error_info = {"type": type(exc).__name__, "message": str(exc)}
            # Reset explicitly — splitting the read into "headers" then
            # "body" stages (for the size cap above) means status_code can
            # already be set from a real response by the time the body read
            # fails mid-stream. A stale status_code here would otherwise
            # leak into the final observation even though received_response
            # stays False and the artifact correctly records only an
            # "error" key, producing a confident GRANTED/DENIED
            # classification from evidence the artifact itself says failed.
            status_code = None

        transcript: Dict[str, Any] = {
            "observation_id": observation_id,
            "action_ref": action.action_id,
            "role": role.value,
            "identity": identity,
            "captured_at": captured_at.isoformat(),
            "request": {
                "method": action.method,
                "url": _redact_url_query(sent_url, sensitive_body_keys),
                "params": _redact_body(params, sensitive_body_keys),
                "body": _redact_body(request_body, sensitive_body_keys),
                "headers": request_headers,
            },
        }
        if received_response:
            transcript["response"] = {
                "status_code": status_code,
                "headers": _redact_headers(response_headers_raw, self._sensitive_header_names),
                "body": response_text,
                "body_encoding": body_encoding,
            }
            if response_truncated:
                transcript["response"]["truncated"] = True
                transcript["response"]["truncated_reason"] = (
                    f"Response vượt {_MAX_RESPONSE_BYTES} bytes — dừng đọc để tránh hết bộ nhớ, "
                    "phần thân lưu lại chỉ là phần đã đọc trước khi dừng."
                )
        else:
            transcript["error"] = error_info

        # Hash covers exactly the bytes written to disk, so the hash always
        # matches the artifact literally, not some other serialization of it.
        raw_bytes = json.dumps(transcript, indent=2, sort_keys=True).encode("utf-8")
        raw_evidence_hash = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        artifact_path = self._storage_dir / f"{observation_id}.json"
        artifact_path.write_bytes(raw_bytes)

        # Uses sent_url (the REAL resolved URL), not action.target verbatim
        # — same fidelity reasoning as the stored transcript above: marker
        # detection must reflect what was actually on the wire.
        request_text = json.dumps({"url": sent_url, "params": params, "body": request_body})

        # A connection failure (received_response=False) must yield None here,
        # not the same False a real empty/marker-free body would produce —
        # otherwise "we don't know" (no response at all) reads identically to
        # "we checked and it's absent", which would make check_main_predicate
        # (verdict_oracle/predicates.py) call this UNSATISFIED instead of
        # INSUFFICIENT_DATA on a network error. request_contains_marker has
        # no such distinction to make: the request was built and (attempted
        # to be) sent either way, so its content is always known.
        response_contains_marker = _contains_marker(response_text, marker) if received_response else None
        if response_truncated and response_contains_marker is False:
            # A marker sitting past the truncation cutoff would otherwise
            # come back as a confident "absent" — a false negative caused
            # by the byte cap, not evidence of absence. A definitive True
            # is left alone: finding the marker in what WAS read is still a
            # real positive signal regardless of truncation.
            response_contains_marker = None

        access_result = _classify_access_result(status_code)
        observation = NormalizedObservation(
            observation_id=observation_id,
            action_ref=action.action_id,
            role=role,
            captured_at=captured_at,
            identity=identity,
            execution_id=self._execution_id,
            target_id=self._target_id,
            target_revision_id=self._target_revision_id,
            channel=EvidenceChannel.HTTP_TRANSACTION,
            raw_evidence_size_bytes=len(raw_bytes),
            raw_evidence_hash=raw_evidence_hash,
            raw_evidence_ref=str(artifact_path),
            access_result=access_result,
            status_code=status_code,
            response_contains_marker=response_contains_marker,
            request_contains_marker=_contains_marker(request_text, marker),
        )

        if self._context_store is not None:
            # SPEC §4.6 write path, step 1. Deliberately best-effort: losing
            # this bookkeeping row is not remotely as severe as losing the
            # real evidence above (raw_bytes is already durably written by
            # this point), so a Context Store hiccup (e.g. disk full, DB
            # locked) must never make an otherwise-successful capture()
            # look like it failed to the caller. Description is a MECHANICAL
            # summary only (action + access_result/status_code) — no marker
            # value, no credential, no response body — matching this
            # module's "không diễn giải, không kết luận" principle and
            # SPEC §4.6's explicit "never store" list.
            #
            # Strips the query string AND any userinfo UNCONDITIONALLY,
            # regardless of caller-declared sensitive_body_keys — unlike the
            # raw artifact, this store's "never store" list is absolute
            # (a blind marker has no query-param "key name" an operator
            # would think to declare). Known residual gap: a marker/secret
            # embedded in the URL PATH itself would still leak — this
            # codebase's own blind-marker usage plants markers in body/query
            # content, not path segments, so this covers the realistic case.
            target_url_parts = urlsplit(action.target)
            target_without_query = urlunsplit(
                target_url_parts._replace(netloc=_strip_userinfo(target_url_parts.netloc), query="", fragment="")
            )
            try:
                self._context_store.record_unverified_observation(
                    target_id=self._target_id,
                    execution_id=self._execution_id,
                    description=(
                        f"[{role.value}] {action.method} {target_without_query} -> "
                        f"access_result={access_result.value}, status_code={status_code}"
                    ),
                    revision=self._target_revision_id,
                )
            except RuntimeError:
                pass

        return observation

    def _rewrite_artifact_response_body(
        self, observation: NormalizedObservation, raw: Dict[str, Any], new_body: str
    ) -> NormalizedObservation:
        """Overwrites the stored response body of an already-written
        artifact with `new_body`, recomputes hash/size to match the new
        bytes, and returns an updated observation copy. `raw` is the
        already-parsed artifact dict (the caller already has it in hand,
        no need to re-read the file). Shared by login()'s 3 body-rewrite
        cases: successful extraction (redact just the known path), a null/
        invalid extracted value (same, still a known path), and a failed
        extraction (redact the WHOLE body — see login()'s docstring for why
        these need different treatment).
        """
        raw["response"]["body"] = new_body
        rewritten_bytes = json.dumps(raw, indent=2, sort_keys=True).encode("utf-8")
        Path(observation.raw_evidence_ref).write_bytes(rewritten_bytes)
        return observation.model_copy(
            update={
                "raw_evidence_hash": "sha256:" + hashlib.sha256(rewritten_bytes).hexdigest(),
                "raw_evidence_size_bytes": len(rewritten_bytes),
            }
        )

    def login(
        self,
        identity: str,
        login_action: ActionSpec,
        token_json_path: Optional[str] = None,
        token_header: str = "Authorization",
        token_prefix: str = "Bearer ",
        sensitive_request_keys: Optional[Set[str]] = None,
    ) -> NormalizedObservation:
        """Executes `login_action` through `identity`'s own client. Handles
        BOTH real-world session styles generically — parameterized by the
        caller, nothing about any specific target hardcoded here:

        - Cookie-based sessions: if the response sets a cookie, httpx's own
          jar on this identity's client captures and auto-replays it on
          every later request — nothing else to do, this already works with
          no extra arguments.
        - Bearer-token-in-body sessions (JWT etc.): confirmed live that real
          OWASP Juice Shop's `/rest/user/login` returns
          {"authentication": {"token": "..."}} in the JSON body, not a
          cookie at all — a very common modern-API pattern this module must
          also support to be genuinely target-agnostic. Pass
          `token_json_path` (a dotted path into the response JSON, e.g.
          "authentication.token"; numeric segments index into a list); the
          extracted value is set as a default header (`token_header`,
          prefixed with `token_prefix`) on this identity's client, sent on
          every later request the same way a cookie would be. `login_action`
          still only describes THIS target's login request shape (URL/
          method/body) — the path/header name/prefix are the only target-
          specific knobs, all caller-supplied config, not code written per
          target. Re-`login()`-ing the same identity with a DIFFERENT
          `token_header` removes the stale header instead of leaving both
          attached.

        Redaction — a login transcript legitimately needs to record that a
        login happened, but must not store real secrets in the clear:
        - `sensitive_request_keys` (e.g. {"password"}): those keys in
          `login_action.parameters` are redacted in the STORED request body
          — caller-supplied because a login body's shape is entirely
          target-specific, this module can't guess which keys are secrets
          (same reasoning as Policy Service's caller-declared `params:`
          allowlist).
        - The token value at `token_json_path` is always redacted in the
          stored artifact once extracted — that path IS the secret, by
          definition.
        - If extraction FAILS (wrong path, login_action itself failed, a
          typo'd path segment), the ENTIRE response body is wiped from the
          artifact instead of just the one path: `capture()` below always
          writes the full, unredacted body to disk first, and a failed
          extraction means we don't know exactly where (or whether) a real
          secret sits in that body — failing safe means treating the whole
          body as sensitive, not leaving it in the clear because the one
          path we'd have redacted couldn't be confirmed.
        - If the value AT `token_json_path` resolves but is null, empty, or
          not a string, this raises instead of silently building a broken
          credential (e.g. literal header value "Bearer None") that would
          then be sent on every subsequent request with no error anywhere
          — see the check below.

        Captured as evidence (role=SETUP) like any other action either way,
        for reproducibility, and to keep this out of the 3 real predicate
        groups (see ObservationRole.SETUP).
        """
        observation = self.capture(
            login_action,
            role=ObservationRole.SETUP,
            identity=identity,
            sensitive_body_keys=sensitive_request_keys,
        )
        if not token_json_path:
            return observation

        raw = json.loads(Path(observation.raw_evidence_ref).read_text(encoding="utf-8"))
        response_body = raw.get("response", {}).get("body")
        if response_body is None:
            raise ValueError(
                f"login() cho identity '{identity}': không có response body để trích token theo "
                f"đường dẫn '{token_json_path}' — login_action có thể đã thất bại, xem lỗi ở "
                f"{observation.raw_evidence_ref}."
            )

        path_parts = token_json_path.split(".")
        try:
            parsed = json.loads(response_body)
            token: Any = parsed
            for part in path_parts:
                token = token[int(part)] if isinstance(token, list) else token[part]
        except (KeyError, TypeError, IndexError, ValueError) as exc:
            # Fail SAFE: we don't know exactly where (or whether) a real
            # secret sits in this body, so wipe ALL of it rather than leave
            # a possibly-real secret in the clear forever — see this
            # method's own docstring for the full reasoning.
            self._rewrite_artifact_response_body(
                observation, raw, f"{_REDACTED_PLACEHOLDER} (token_json_path extraction thất bại)"
            )
            raise ValueError(
                f"login() cho identity '{identity}': không trích được token theo đường dẫn "
                f"'{token_json_path}' — {type(exc).__name__}: {exc}. Response body đã bị redact "
                f"TOÀN BỘ trên đĩa (không rõ secret nằm ở đâu nên xoá phòng ngừa) — chỉ còn status "
                f"code/headers tại {observation.raw_evidence_ref} để chẩn đoán (có thể login đã "
                "thất bại, hoặc path sai)."
            ) from exc

        if not isinstance(token, str) or not token:
            # A resolved-but-null/empty/non-string value would otherwise
            # become a literal broken credential (e.g. "Bearer None") sent
            # silently on every later request — if this identity is the
            # positive_control, SPEC's rule ("thiếu positive control thì
            # không có CONFIRMED") means a real vulnerability could never
            # be CONFIRMED, misattributed to "the system correctly requires
            # auth" instead of "our own login was broken." The path DID
            # resolve here (unlike the exception case above), so redact
            # just that, not the whole body.
            self._rewrite_artifact_response_body(
                observation, raw, json.dumps(_redact_json_path(parsed, path_parts))
            )
            raise ValueError(
                f"login() cho identity '{identity}': giá trị tại đường dẫn '{token_json_path}' "
                f"rỗng hoặc không phải string (kiểu thực tế: {type(token).__name__}) — từ chối dùng "
                "làm token thật, tránh gửi credential hỏng (vd 'Bearer None') trên mọi request sau "
                f"đó mà không có lỗi nào báo. Xem {observation.raw_evidence_ref}."
            )

        previous_header = self._token_header_by_identity.get(identity)
        client = self._client_for(identity)
        if previous_header and previous_header.lower() != token_header.lower():
            client.headers.pop(previous_header, None)
        self._token_header_by_identity[identity] = token_header
        self._sensitive_header_names.add(token_header.lower())
        client.headers[token_header] = f"{token_prefix}{token}"

        # Scrub the token out of the already-written login artifact — it
        # must not sit in the clear on disk once extracted. Hash/size are
        # recomputed since the file's actual bytes just changed.
        return self._rewrite_artifact_response_body(
            observation, raw, json.dumps(_redact_json_path(parsed, path_parts))
        )

    def close(self) -> None:
        if self._owns_clients:
            for client in self._clients.values():
                client.close()
        self._closed = True

    def __enter__(self) -> "EvidenceHarness":
        return self

    def __exit__(self, *_exc_info: Any) -> None:
        self.close()
