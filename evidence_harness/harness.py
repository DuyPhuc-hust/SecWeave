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

Identity/session handling (closes the gap noted in earlier commits — real
requests used to be sent identically regardless of stated identity): each
identity gets its own httpx.Client/cookie jar (see EvidenceHarness's own
docstring), and login() establishes a session generically — it just executes
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
across everything for one execution (capture() calls, and eventually a real
Cost Service / Execute loop), same as it shares one execution_id.
"""

import copy
import hashlib
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import httpx

from shared.id_generator import generate_id
from shared.kill_switch import ExecutionStoppedError, KillSwitch
from shared.models.action import ActionSpec
from shared.models.observation import (
    AccessResult,
    EvidenceChannel,
    NormalizedObservation,
    ObservationRole,
)

# Minimal safety floor, not the real redaction catalog (see module docstring).
# Extended per-instance by login() when a caller uses a custom token_header —
# real gap found via review: a hardcoded 3-name set only ever redacted
# "Authorization", so a custom header name (e.g. "X-Access-Token", common for
# real APIs) leaked the live token in plaintext on every subsequent request,
# not just the login itself.
_BASE_REDACTED_HEADERS = {"authorization", "cookie", "set-cookie"}
_REDACTED_PLACEHOLDER = "<redacted>"

# Methods conventionally read via query string rather than a body. Not part
# of SPEC — ActionSpec.parameters doesn't say whether it's a query string or
# a body (a gap, like the ActionSpec/role one flagged in observation.py), so
# this is a documented, simple heuristic rather than a guess made silently.
_QUERY_STRING_METHODS = {"GET", "HEAD", "DELETE"}


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
    return marker in text


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
    ) -> None:
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
        # `http_client`: one SHARED instance/jar for EVERY identity — ONLY
        # for tests that genuinely don't care about identity isolation
        # (testing something else entirely, e.g. a single-identity capture()
        # scenario). Real footgun flagged via review: this silently defeats
        # per-identity cookie/token isolation if used for anything else —
        # login("alice", ...) and login("bob", ...) would clobber the SAME
        # jar/headers, since _client_for() ignores the identity argument
        # entirely on this path. No production call site uses this today;
        # a real (or realistic multi-identity test) scenario MUST use
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
        # the real path via a hard link. Real race found via review: the
        # previous open(path, "x") approach created the file (zero-length)
        # and wrote to it as 2 separate steps — a second process racing in
        # between could hit FileExistsError on a still-EMPTY file and crash
        # on json.loads() reading it, instead of getting a value. os.link()
        # only ever points the destination at an already-fully-written file,
        # so a racing reader can never observe a partial manifest — same
        # "exactly one winner" semantics, no TOCTOU window.
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
        declared rather than guessed. Only affects the STORED transcript,
        never the real request actually sent.

        Raises ExecutionStoppedError instead of sending anything if this
        instance was given a KillSwitch and it is currently STOPPED (SPEC:
        "Agent hoặc model không có quyền từ chối lệnh dừng") — see
        shared/kill_switch.py for the full design and its stated limits
        (this is a check-before-send guard, not a mid-flight abort).
        """
        if self._kill_switch is not None and self._kill_switch.is_stopped:
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
        received_response = False
        request_headers: Dict[str, str] = {}
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
            request_headers = _redact_headers(dict(request.headers), self._sensitive_header_names)
            response = client.send(request)
            status_code = response.status_code
            response_text = response.text
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

        transcript: Dict[str, Any] = {
            "observation_id": observation_id,
            "action_ref": action.action_id,
            "role": role.value,
            "identity": identity,
            "captured_at": captured_at.isoformat(),
            "request": {
                "method": action.method,
                "url": action.target,
                "params": _redact_body(params, sensitive_body_keys),
                "body": _redact_body(request_body, sensitive_body_keys),
                "headers": request_headers,
            },
        }
        if received_response:
            transcript["response"] = {
                "status_code": status_code,
                "headers": _redact_headers(dict(response.headers), self._sensitive_header_names),
                "body": response_text,
            }
        else:
            transcript["error"] = error_info

        # Hash covers exactly the bytes written to disk, so the hash always
        # matches the artifact literally, not some other serialization of it.
        raw_bytes = json.dumps(transcript, indent=2, sort_keys=True).encode("utf-8")
        raw_evidence_hash = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        artifact_path = self._storage_dir / f"{observation_id}.json"
        artifact_path.write_bytes(raw_bytes)

        request_text = json.dumps({"url": action.target, "params": params, "body": request_body})

        # A connection failure (received_response=False) must yield None here,
        # not the same False a real empty/marker-free body would produce —
        # otherwise "we don't know" (no response at all) reads identically to
        # "we checked and it's absent", which would make check_main_predicate
        # (verdict_oracle/predicates.py) call this UNSATISFIED instead of
        # INSUFFICIENT_DATA on a network error. request_contains_marker has
        # no such distinction to make: the request was built and (attempted
        # to be) sent either way, so its content is always known.
        response_contains_marker = _contains_marker(response_text, marker) if received_response else None

        return NormalizedObservation(
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
            access_result=_classify_access_result(status_code),
            status_code=status_code,
            response_contains_marker=response_contains_marker,
            request_contains_marker=_contains_marker(request_text, marker),
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
          stored artifact once extracted — real gap found via review: the
          whole point of that path is "this is the secret", but it was
          previously left in the clear in the login's own raw response body.

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
            raise ValueError(
                f"login() cho identity '{identity}': không trích được token theo đường dẫn "
                f"'{token_json_path}' — {type(exc).__name__}: {exc}. Xem response thật tại "
                f"{observation.raw_evidence_ref} (có thể login đã thất bại, hoặc path sai)."
            ) from exc

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
        redacted_body = json.dumps(_redact_json_path(parsed, path_parts))
        raw["response"]["body"] = redacted_body
        redacted_bytes = json.dumps(raw, indent=2, sort_keys=True).encode("utf-8")
        Path(observation.raw_evidence_ref).write_bytes(redacted_bytes)
        return observation.model_copy(
            update={
                "raw_evidence_hash": "sha256:" + hashlib.sha256(redacted_bytes).hexdigest(),
                "raw_evidence_size_bytes": len(redacted_bytes),
            }
        )

    def close(self) -> None:
        if self._owns_clients:
            for client in self._clients.values():
                client.close()

    def __enter__(self) -> "EvidenceHarness":
        return self

    def __exit__(self, *_exc_info: Any) -> None:
        self.close()
