import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from evidence_harness.harness import _MAX_RESPONSE_BYTES, EvidenceHarness
from shared.models.action import ActionSpec, ActionType
from shared.models.observation import AccessResult, EvidenceChannel, ObservationRole


def _action(**overrides) -> ActionSpec:
    defaults = dict(
        type=ActionType.READ_ONLY,
        method="GET",
        target="https://target.example.com/api/objects/42",
        description="Read object 42.",
    )
    defaults.update(overrides)
    return ActionSpec(**defaults)


def _harness(tmp_path, handler) -> EvidenceHarness:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return EvidenceHarness(
        execution_id="exec_test1",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path),
        http_client=client,
    )


def test_capture_granted_populates_observation_from_real_response(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 42, "owner": "alice"})

    harness = _harness(tmp_path, handler)
    action = _action()
    observation = harness.capture(action, role=ObservationRole.MAIN, identity="tester@example.com")

    assert observation.access_result == AccessResult.GRANTED
    assert observation.status_code == 200
    assert observation.channel == EvidenceChannel.HTTP_TRANSACTION
    assert observation.identity == "tester@example.com"
    assert observation.execution_id == "exec_test1"
    assert observation.target_id == "tgt_1"
    assert observation.target_revision_id == "rev_1"
    assert observation.action_ref == action.action_id
    assert observation.role == ObservationRole.MAIN


def test_capture_denied_on_401_and_403(tmp_path):
    for status in (401, 403):

        def handler(request: httpx.Request, _status=status) -> httpx.Response:
            return httpx.Response(_status)

        harness = _harness(tmp_path / str(status), handler)
        observation = harness.capture(_action(), role=ObservationRole.DENIED_CONTROL)
        assert observation.access_result == AccessResult.DENIED
        assert observation.status_code == status


def test_capture_ambiguous_on_404_and_500(tmp_path):
    for status in (404, 500):

        def handler(request: httpx.Request, _status=status) -> httpx.Response:
            return httpx.Response(_status)

        harness = _harness(tmp_path, handler)
        observation = harness.capture(_action(), role=ObservationRole.MAIN)
        assert observation.access_result == AccessResult.AMBIGUOUS
        assert observation.status_code == status


def test_capture_survives_connection_failure_as_ambiguous_with_no_status(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN)

    assert observation.access_result == AccessResult.AMBIGUOUS
    assert observation.status_code is None

    raw = json.loads(Path(observation.raw_evidence_ref).read_bytes())
    assert raw["error"]["type"] == "ConnectError"


def test_capture_writes_raw_artifact_whose_hash_matches_recomputed_hash(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN)

    artifact_path = Path(observation.raw_evidence_ref)
    assert artifact_path.exists()
    raw_bytes = artifact_path.read_bytes()
    assert len(raw_bytes) == observation.raw_evidence_size_bytes
    recomputed = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
    assert recomputed == observation.raw_evidence_hash


def test_capture_redacts_authorization_and_cookie_headers_on_disk(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Set-Cookie": "session=super-secret-value",
                "X-Custom": "keep-me",
            },
            json={"ok": True},
        )

    harness = _harness(tmp_path, handler)
    observation = harness.capture(
        _action(parameters={}),
        role=ObservationRole.MAIN,
    )

    raw_text = Path(observation.raw_evidence_ref).read_text()
    assert "super-secret-value" not in raw_text
    assert "keep-me" in raw_text


def test_capture_sends_get_parameters_as_query_string_not_body(tmp_path):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = request.content
        return httpx.Response(200)

    harness = _harness(tmp_path, handler)
    action = _action(method="GET", parameters={"filter": "mine"})
    harness.capture(action, role=ObservationRole.MAIN)

    assert "filter=mine" in captured["url"]
    assert captured["body"] == b""


def test_capture_sends_post_parameters_as_json_body_not_query_string(tmp_path):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = request.content
        return httpx.Response(201)

    harness = _harness(tmp_path, handler)
    action = _action(
        method="POST",
        type=ActionType.TEST_DATA_CREATION,
        parameters={"name": "bait-item"},
    )
    harness.capture(action, role=ObservationRole.POSITIVE_CONTROL)

    assert "name=" not in captured["url"]
    assert b"bait-item" in captured["body"]


def test_capture_marker_present_in_response_absent_from_request(tmp_path):
    marker = "sw-marker-abc123"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"leaked_field": marker})

    harness = _harness(tmp_path, handler)
    action = _action(parameters={"filter": "unrelated"})
    observation = harness.capture(action, role=ObservationRole.MAIN, marker=marker)

    assert observation.response_contains_marker is True
    assert observation.request_contains_marker is False


def test_capture_marker_is_insufficient_data_not_false_on_connection_failure(tmp_path):
    # Regression: a connection failure means "no response to check" — this
    # must stay None (insufficient_data downstream), not collapse into the
    # same False a real marker-free response would produce (which would
    # misreport the predicate as UNSATISFIED instead of INSUFFICIENT_DATA).
    marker = "sw-marker-xyz789"

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    harness = _harness(tmp_path, handler)
    action = _action(parameters={"filter": "unrelated"})
    observation = harness.capture(action, role=ObservationRole.MAIN, marker=marker)

    assert observation.response_contains_marker is None
    assert observation.request_contains_marker is False


def test_capture_marker_none_when_scenario_does_not_use_one(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN, marker=None)

    assert observation.response_contains_marker is None
    assert observation.request_contains_marker is None


def test_two_captures_in_same_execution_get_distinct_observation_ids_and_files(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    harness = _harness(tmp_path, handler)
    obs1 = harness.capture(_action(), role=ObservationRole.MAIN)
    obs2 = harness.capture(_action(), role=ObservationRole.POSITIVE_CONTROL)

    assert obs1.observation_id != obs2.observation_id
    assert obs1.raw_evidence_ref != obs2.raw_evidence_ref
    assert Path(obs1.raw_evidence_ref).exists()
    assert Path(obs2.raw_evidence_ref).exists()


# ----- generate_marker() / seed manifest (SPEC §4.3.4) -----


def _harness_no_client(tmp_path, execution_id="exec_marker_test") -> EvidenceHarness:
    return EvidenceHarness(
        execution_id=execution_id,
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path),
    )


def test_generate_marker_is_stable_across_repeated_calls_same_instance(tmp_path):
    harness = _harness_no_client(tmp_path)
    first = harness.generate_marker()
    second = harness.generate_marker()
    assert first == second


def test_generate_marker_persists_to_seed_manifest_with_execution_id(tmp_path):
    harness = _harness_no_client(tmp_path, execution_id="exec_abc")
    marker = harness.generate_marker()

    manifest_path = tmp_path / "exec_abc" / "seed_manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text())
    assert manifest["marker"] == marker
    assert manifest["execution_id"] == "exec_abc"


def test_generate_marker_recovered_by_a_new_harness_instance_same_execution(tmp_path):
    # Simulates a run spanning two separate process invocations (e.g. one CLI
    # call seeds bait data, a later CLI call runs the actual exploit action)
    # — both must see the exact same marker, or every check silently fails.
    first_harness = _harness_no_client(tmp_path, execution_id="exec_shared")
    marker = first_harness.generate_marker()

    second_harness = _harness_no_client(tmp_path, execution_id="exec_shared")
    assert second_harness.generate_marker() == marker


def test_generate_marker_does_not_overwrite_a_concurrently_written_manifest(tmp_path):
    # Simulates the race: another process wins and writes the manifest file
    # in between this harness checking "does it exist" and creating it. The
    # exclusive-create ("x" mode) must make this harness back off and adopt
    # the winner's value instead of silently producing 2 different markers
    # for the same execution_id.
    harness = _harness_no_client(tmp_path, execution_id="exec_race")
    winner_manifest = {
        "execution_id": "exec_race",
        "marker": "already-seeded-by-another-process",
        "generated_at": "2026-08-14T00:00:00+00:00",
    }
    harness._seed_manifest_path.write_text(json.dumps(winner_manifest))

    assert harness.generate_marker() == "already-seeded-by-another-process"


def test_generate_marker_concurrent_calls_never_crash_and_agree_on_one_value(tmp_path):
    # Real regression: the previous open(path, "x") approach created the
    # destination file and wrote its content as 2 separate steps — a second
    # thread racing in between could hit FileExistsError on a still-EMPTY
    # file and crash on json.loads() reading it back, instead of getting a
    # value. Uses a real thread barrier to force genuine concurrent access
    # (not just "usually fast enough not to overlap").
    import threading

    barrier = threading.Barrier(8)
    results = []
    errors = []

    def _call():
        try:
            barrier.wait(timeout=5)
            harness = _harness_no_client(tmp_path, execution_id="exec_concurrent")
            results.append(harness.generate_marker())
        except Exception as exc:  # noqa: BLE001 - test needs to see ANY failure
            errors.append(exc)

    threads = [threading.Thread(target=_call) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert errors == []
    assert len(results) == 8
    assert len(set(results)) == 1


def test_capture_setup_role_produces_an_observation_but_is_ignored_by_predicates(tmp_path):
    from verdict_oracle.predicates import evaluate_predicates

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201)

    harness = _harness(tmp_path, handler)
    marker = "sw-marker-seed-test"
    seed_action = _action(
        method="POST",
        type=ActionType.TEST_DATA_CREATION,
        parameters={"note": marker},
    )
    setup_observation = harness.capture(seed_action, role=ObservationRole.SETUP)

    assert setup_observation.role == ObservationRole.SETUP
    assert Path(setup_observation.raw_evidence_ref).exists()

    # A SETUP-only observation list must still yield insufficient_data for
    # all 3 real predicate groups (never crash, never get miscounted as one
    # of them).
    results = evaluate_predicates([setup_observation])
    assert len(results) == 3
    groups = {r.group for r in results}
    assert groups == {ObservationRole.MAIN, ObservationRole.POSITIVE_CONTROL, ObservationRole.DENIED_CONTROL}


def test_capture_survives_invalid_url_without_crashing(tmp_path):
    # Real regression: httpx.InvalidURL (e.g. a malformed port — a realistic
    # LLM-authored-target failure mode) is NOT a subclass of httpx.HTTPError,
    # so `except httpx.HTTPError` alone let it escape uncaught, crashing
    # capture() before any artifact was written — losing evidence entirely,
    # the exact thing this method's docstring promises never happens.
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - never reached
        return httpx.Response(200)

    harness = _harness(tmp_path, handler)
    action = _action(target="https://staging.example.com:8O80/api/objects/1")

    observation = harness.capture(action, role=ObservationRole.MAIN)

    assert observation.status_code is None
    assert observation.access_result == AccessResult.AMBIGUOUS
    raw = json.loads(Path(observation.raw_evidence_ref).read_bytes())
    assert raw["error"]["type"] == "InvalidURL"


# ----- per-identity cookie jars / login() -----


def _harness_with_isolated_identities(tmp_path, handler) -> EvidenceHarness:
    # http_client_factory (not http_client) so each identity gets its OWN
    # MockTransport-backed client/jar — real isolation, still no network.
    return EvidenceHarness(
        execution_id="exec_identity_test",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path),
        http_client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_login_then_capture_carries_the_session_cookie(tmp_path):
    seen_cookies = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookies.append(request.headers.get("cookie"))
        if request.url.path == "/login":
            return httpx.Response(200, headers={"Set-Cookie": "session=alice-token"})
        return httpx.Response(200)

    harness = _harness_with_isolated_identities(tmp_path, handler)
    login_action = _action(method="POST", target="https://target.example.com/login", type=ActionType.TEST_DATA_CREATION)
    harness.login("alice", login_action)

    harness.capture(_action(), role=ObservationRole.POSITIVE_CONTROL, identity="alice")

    assert seen_cookies[0] is None  # login request itself carried no cookie yet
    assert seen_cookies[1] == "session=alice-token"  # follow-up request as alice carries it


def test_two_identities_have_isolated_cookie_jars(tmp_path):
    seen_cookies = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            who = request.url.params.get("as")
            return httpx.Response(200, headers={"Set-Cookie": f"session={who}-token"})
        seen_cookies.append(request.headers.get("cookie"))
        return httpx.Response(200)

    harness = _harness_with_isolated_identities(tmp_path, handler)
    harness.login("alice", _action(method="GET", target="https://target.example.com/login?as=alice"))
    harness.login("bob", _action(method="GET", target="https://target.example.com/login?as=bob"))

    harness.capture(_action(), role=ObservationRole.POSITIVE_CONTROL, identity="alice")
    harness.capture(_action(), role=ObservationRole.DENIED_CONTROL, identity="bob")

    assert seen_cookies == ["session=alice-token", "session=bob-token"]


def test_capture_defaults_to_anonymous_identity_with_no_cookies(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("cookie") is None
        return httpx.Response(200)

    harness = _harness_with_isolated_identities(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN)
    assert observation.identity == "anonymous"


def test_login_extracts_bearer_token_from_json_response_body(tmp_path):
    # Real-world pattern confirmed live against OWASP Juice Shop:
    # /rest/user/login returns {"authentication": {"token": "..."}} in the
    # JSON body, not a Set-Cookie at all — the cookie-jar mechanism alone
    # doesn't cover this very common modern-API auth style.
    seen_auth_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, json={"authentication": {"token": "jwt-abc123"}})
        seen_auth_headers.append(request.headers.get("authorization"))
        return httpx.Response(200)

    harness = _harness_with_isolated_identities(tmp_path, handler)
    harness.login(
        "alice",
        _action(method="POST", target="https://target.example.com/login", type=ActionType.TEST_DATA_CREATION),
        token_json_path="authentication.token",
    )
    harness.capture(_action(), role=ObservationRole.POSITIVE_CONTROL, identity="alice")

    assert seen_auth_headers == ["Bearer jwt-abc123"]


def test_login_bearer_token_is_isolated_per_identity(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            who = request.url.params.get("as")
            return httpx.Response(200, json={"authentication": {"token": f"jwt-{who}"}})
        return httpx.Response(200, json={"seen_auth": request.headers.get("authorization")})

    harness = _harness_with_isolated_identities(tmp_path, handler)
    harness.login(
        "alice",
        _action(method="GET", target="https://target.example.com/login?as=alice"),
        token_json_path="authentication.token",
    )
    harness.login(
        "bob",
        _action(method="GET", target="https://target.example.com/login?as=bob"),
        token_json_path="authentication.token",
    )

    obs_alice = harness.capture(_action(), role=ObservationRole.POSITIVE_CONTROL, identity="alice")
    obs_bob = harness.capture(_action(), role=ObservationRole.DENIED_CONTROL, identity="bob")

    raw_alice = json.loads(Path(obs_alice.raw_evidence_ref).read_text())
    raw_bob = json.loads(Path(obs_bob.raw_evidence_ref).read_text())
    assert "jwt-alice" in raw_alice["response"]["body"]
    assert "jwt-bob" in raw_bob["response"]["body"]


def test_login_raises_clean_error_when_token_json_path_is_missing_from_response(tmp_path):
    import pytest

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    harness = _harness_with_isolated_identities(tmp_path, handler)
    # Real gap found via review: this used to escape as a raw KeyError with
    # no context — now a clean ValueError naming the path, the identity, and
    # where to look (the raw artifact), same spirit as the "no response
    # body" case that was already handled cleanly.
    with pytest.raises(ValueError, match="authentication.token"):
        harness.login(
            "alice",
            _action(method="POST", target="https://target.example.com/login"),
            token_json_path="authentication.token",
        )


def test_login_raises_clean_error_on_non_json_response_body(tmp_path):
    import pytest

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>not json</html>")

    harness = _harness_with_isolated_identities(tmp_path, handler)
    with pytest.raises(ValueError, match="authentication.token"):
        harness.login(
            "alice",
            _action(method="POST", target="https://target.example.com/login"),
            token_json_path="authentication.token",
        )


def test_login_extracts_token_from_a_list_index_path(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"tokens": [{"value": "jwt-from-list"}]})

    harness = _harness_with_isolated_identities(tmp_path, handler)
    harness.login(
        "alice",
        _action(method="POST", target="https://target.example.com/login"),
        token_json_path="tokens.0.value",
    )
    client = harness._client_for("alice")
    assert client.headers["Authorization"] == "Bearer jwt-from-list"


def test_relogin_with_different_token_header_removes_stale_header(tmp_path):
    responses = iter([{"token": "first-token"}, {"token": "second-token"}])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, json=next(responses))
        return httpx.Response(200)

    harness = _harness_with_isolated_identities(tmp_path, handler)
    harness.login(
        "alice",
        _action(method="POST", target="https://target.example.com/login"),
        token_json_path="token",
        token_header="X-Legacy-Token",
        token_prefix="",
    )
    harness.login(
        "alice",
        _action(method="POST", target="https://target.example.com/login"),
        token_json_path="token",
        token_header="Authorization",
    )
    client = harness._client_for("alice")
    assert "X-Legacy-Token" not in client.headers
    assert client.headers["Authorization"] == "Bearer second-token"


def test_login_redacts_password_in_request_body_when_declared_sensitive(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token": "irrelevant"})

    harness = _harness_with_isolated_identities(tmp_path, handler)
    login_action = _action(
        method="POST",
        target="https://target.example.com/login",
        type=ActionType.TEST_DATA_CREATION,
        parameters={"username": "alice", "password": "hunter2-super-secret"},
    )
    observation = harness.login(
        "alice", login_action, token_json_path="token", sensitive_request_keys={"password"}
    )

    raw_text = Path(observation.raw_evidence_ref).read_text()
    assert "hunter2-super-secret" not in raw_text
    assert "alice" in raw_text  # non-sensitive keys stay untouched


def test_login_redacts_extracted_token_from_stored_response_body(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"authentication": {"token": "super-secret-jwt-value"}})

    harness = _harness_with_isolated_identities(tmp_path, handler)
    observation = harness.login(
        "alice",
        _action(method="POST", target="https://target.example.com/login", type=ActionType.TEST_DATA_CREATION),
        token_json_path="authentication.token",
    )

    raw_text = Path(observation.raw_evidence_ref).read_text()
    assert "super-secret-jwt-value" not in raw_text
    # Hash/size returned must match the actually-rewritten (redacted) file.
    raw_bytes = Path(observation.raw_evidence_ref).read_bytes()
    assert observation.raw_evidence_size_bytes == len(raw_bytes)
    assert observation.raw_evidence_hash == "sha256:" + hashlib.sha256(raw_bytes).hexdigest()


def test_custom_token_header_is_redacted_on_every_subsequent_request(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, json={"token": "TOTALLY-SECRET-API-TOKEN"})
        return httpx.Response(200)

    harness = _harness_with_isolated_identities(tmp_path, handler)
    harness.login(
        "alice",
        _action(method="POST", target="https://target.example.com/login", type=ActionType.TEST_DATA_CREATION),
        token_json_path="token",
        token_header="X-Access-Token",
        token_prefix="",
    )
    observation = harness.capture(_action(), role=ObservationRole.MAIN, identity="alice")

    raw_text = Path(observation.raw_evidence_ref).read_text()
    assert "TOTALLY-SECRET-API-TOKEN" not in raw_text


def test_login_bearer_token_is_redacted_on_disk(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, json={"authentication": {"token": "super-secret-jwt-value"}})
        return httpx.Response(200)

    harness = _harness_with_isolated_identities(tmp_path, handler)
    harness.login(
        "alice",
        _action(method="POST", target="https://target.example.com/login", type=ActionType.TEST_DATA_CREATION),
        token_json_path="authentication.token",
    )
    observation = harness.capture(_action(), role=ObservationRole.MAIN, identity="alice")

    raw_text = Path(observation.raw_evidence_ref).read_text()
    assert "super-secret-jwt-value" not in raw_text


def test_request_cookie_header_is_redacted_on_disk(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, headers={"Set-Cookie": "session=super-secret-cookie-value"})
        return httpx.Response(200)

    harness = _harness_with_isolated_identities(tmp_path, handler)
    harness.login("alice", _action(method="GET", target="https://target.example.com/login"))
    observation = harness.capture(_action(), role=ObservationRole.MAIN, identity="alice")

    raw_text = Path(observation.raw_evidence_ref).read_text()
    assert "super-secret-cookie-value" not in raw_text
    assert observation.identity == "alice"


def test_capture_succeeds_normally_when_kill_switch_present_but_running(tmp_path):
    # A KillSwitch being wired in must not change behavior at all while it's
    # RUNNING — only STOPPED should ever cause capture() to refuse (see
    # tests/test_kill_switch.py's cross-module test for the STOPPED case).
    from shared.kill_switch import KillSwitch

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    kill_switch = KillSwitch(execution_id="exec_test1", storage_dir=str(tmp_path / "kill_switch"))
    kill_switch.start()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    harness = EvidenceHarness(
        execution_id="exec_test1",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path / "evidence"),
        http_client=client,
        kill_switch=kill_switch,
    )

    observation = harness.capture(_action(), role=ObservationRole.MAIN)
    assert observation.access_result == AccessResult.GRANTED


def test_capture_never_refuses_when_no_kill_switch_is_given(tmp_path):
    # Default behavior (kill_switch=None) is unchanged from before this
    # feature existed — every other test in this file relies on this too.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN)
    assert observation.access_result == AccessResult.GRANTED


# ----- Regression tests: 2nd independent review of the Evidence Harness core
# (capture()/generate_marker()/redaction) — 8 real gaps found, all fixed. -----


def test_capture_records_the_real_sent_url_not_action_target_verbatim(tmp_path):
    # Real bug found via review: httpx's params= REPLACES (not merges) a
    # URL's own query string for GET/HEAD/DELETE — action.target's own query
    # string is silently dropped from the real outgoing request, but the
    # transcript used to store action.target verbatim as if that's what was
    # sent, a request/artifact fidelity mismatch that could make a real test
    # silently become a no-op while looking identical in the evidence.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    harness = _harness(tmp_path, handler)
    action = _action(
        method="GET",
        target="https://target.example.com/api/objects/42?token=SECRET123",
        parameters={"lang": "en"},
    )
    observation = harness.capture(action, role=ObservationRole.MAIN)

    raw = json.loads(Path(observation.raw_evidence_ref).read_text())
    stored_url = raw["request"]["url"]
    assert "token=SECRET123" not in stored_url  # the real request never carried it
    assert "lang=en" in stored_url  # this is what was actually sent


def test_capture_redacts_a_secret_embedded_in_action_target_query_string(tmp_path):
    # Real gap found via review: a secret directly in action.target's own
    # query string (e.g. a password-reset token) had NO redaction mechanism
    # at all — sensitive_body_keys only ever covered the separate
    # params/body dict, never the URL itself. Uses POST so the target's own
    # query string genuinely passes through unaffected (unlike the GET case
    # above), confirming the redaction applies to what's really sent.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    harness = _harness(tmp_path, handler)
    action = _action(
        method="POST",
        type=ActionType.TEST_DATA_CREATION,
        target="https://target.example.com/reset-password?token=SUPER-SECRET-RESET-TOKEN",
    )
    observation = harness.capture(action, role=ObservationRole.MAIN, sensitive_body_keys={"token"})

    raw_text = Path(observation.raw_evidence_ref).read_text()
    assert "SUPER-SECRET-RESET-TOKEN" not in raw_text


def test_capture_raises_clean_runtime_error_after_close_instead_of_a_confusing_httpx_crash(tmp_path):
    # Real bug found via review: reusing an identity whose client was
    # already closed used to crash with an uncaught httpx-internal
    # RuntimeError ("Cannot send a request, as the client has been closed"),
    # NOT a subclass of httpx.HTTPError/InvalidURL — the same "narrow except
    # clause misses a real failure mode" bug already fixed once for
    # InvalidURL, recurring via a different exception type.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    harness = _harness_with_isolated_identities(tmp_path, handler)
    harness.capture(_action(), role=ObservationRole.MAIN, identity="alice")
    harness.close()

    with pytest.raises(RuntimeError, match="đã close"):
        harness.capture(_action(), role=ObservationRole.MAIN, identity="alice")


def test_login_wipes_entire_response_body_on_disk_when_token_extraction_fails(tmp_path):
    # Real HIGH-severity gap found via review: capture() always writes the
    # full, unredacted response body to disk FIRST; only a SUCCESSFUL
    # extraction used to trigger the redaction rewrite. A failed extraction
    # (wrong path, typo) left a real secret sitting in the clear on disk
    # forever, with the error message even pointing straight at the file.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"authToken": "REAL-SECRET-JWT-VALUE"}})

    harness = _harness_with_isolated_identities(tmp_path, handler)
    login_action = _action(
        method="POST", target="https://target.example.com/login", type=ActionType.TEST_DATA_CREATION
    )

    with pytest.raises(ValueError, match="không trích được token"):
        harness.login("alice", login_action, token_json_path="authentication.token")

    artifact_files = [f for f in harness._storage_dir.glob("*.json") if f.name != "seed_manifest.json"]
    assert len(artifact_files) == 1
    raw_text = artifact_files[0].read_text()
    assert "REAL-SECRET-JWT-VALUE" not in raw_text


def test_capture_raises_cost_cap_exceeded_and_stops_kill_switch_when_cap_reached(tmp_path):
    # Cross-module integration: a CostService wired in must actually refuse
    # the action that would exceed cap AND halt the whole execution via the
    # shared KillSwitch — a CostService that exists but nothing enforces it
    # would be pure decoration, same reasoning as the analogous kill-switch
    # integration test in tests/test_kill_switch.py.
    from shared.cost import CostCapExceededError, CostService
    from shared.kill_switch import KillSwitch
    from shared.models.kill_switch import AutomaticThresholdReason

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    kill_switch = KillSwitch(execution_id="exec_cost", storage_dir=str(tmp_path / "kill_switch"))
    kill_switch.start()
    cost_service = CostService(execution_id="exec_cost", storage_dir=str(tmp_path / "cost"), cap=1)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    harness = EvidenceHarness(
        execution_id="exec_cost",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path / "evidence"),
        http_client=client,
        kill_switch=kill_switch,
        cost_service=cost_service,
    )

    observation = harness.capture(_action(), role=ObservationRole.MAIN)
    assert observation.access_result == AccessResult.GRANTED
    assert len(calls) == 1

    with pytest.raises(CostCapExceededError):
        harness.capture(_action(), role=ObservationRole.MAIN)

    assert len(calls) == 1  # the 2nd action's real request was never sent
    assert kill_switch.is_stopped is True
    stop_entry = kill_switch.read_audit_log()[-1]
    assert stop_entry["source"] == "automatic_threshold"
    assert stop_entry["automatic_threshold_reason"] == AutomaticThresholdReason.ACTION_COUNT_EXCEEDED.value


def test_capture_cost_cap_breach_permanently_halts_via_kill_switch_not_just_the_cost_check(tmp_path):
    # After a cost-triggered stop, a THIRD capture() attempt must be refused
    # by the kill-switch check (ExecutionStoppedError), not the cost check
    # again — proving the two mechanisms actually compose: the kill-switch
    # is what makes the halt STICK, not just a one-off refusal from
    # CostService alone.
    from shared.cost import CostCapExceededError, CostService
    from shared.kill_switch import ExecutionStoppedError, KillSwitch

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    kill_switch = KillSwitch(execution_id="exec_cost2", storage_dir=str(tmp_path / "kill_switch"))
    kill_switch.start()
    cost_service = CostService(execution_id="exec_cost2", storage_dir=str(tmp_path / "cost"), cap=1)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    harness = EvidenceHarness(
        execution_id="exec_cost2",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path / "evidence"),
        http_client=client,
        kill_switch=kill_switch,
        cost_service=cost_service,
    )

    harness.capture(_action(), role=ObservationRole.MAIN)
    with pytest.raises(CostCapExceededError):
        harness.capture(_action(), role=ObservationRole.MAIN)
    with pytest.raises(ExecutionStoppedError):
        harness.capture(_action(), role=ObservationRole.MAIN)


def test_capture_cost_cap_exceeded_without_a_kill_switch_still_refuses_but_does_not_crash(tmp_path):
    # cost_service alone (no kill_switch) must still refuse the over-cap
    # action — the "if self._kill_switch is not None" guard must not skip
    # the refusal itself, only the auto-stop side effect.
    from shared.cost import CostCapExceededError, CostService

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    cost_service = CostService(execution_id="exec_cost3", storage_dir=str(tmp_path / "cost"), cap=1)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    harness = EvidenceHarness(
        execution_id="exec_cost3",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path / "evidence"),
        http_client=client,
        cost_service=cost_service,
    )

    harness.capture(_action(), role=ObservationRole.MAIN)
    with pytest.raises(CostCapExceededError):
        harness.capture(_action(), role=ObservationRole.MAIN)


def test_capture_succeeds_normally_when_cost_service_present_but_within_cap(tmp_path):
    from shared.cost import CostService

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    cost_service = CostService(execution_id="exec_cost4", storage_dir=str(tmp_path / "cost"), cap=10)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    harness = EvidenceHarness(
        execution_id="exec_cost4",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path / "evidence"),
        http_client=client,
        cost_service=cost_service,
    )
    observation = harness.capture(_action(), role=ObservationRole.MAIN)
    assert observation.access_result == AccessResult.GRANTED
    assert cost_service.executed_action_count == 1


def test_capture_does_not_consume_a_cost_slot_when_client_factory_raises_before_send(tmp_path):
    # Real bug found via independent review: the cost check used to run
    # BEFORE self._client_for(identity) — so a harness-internal failure
    # completely unrelated to the target (a broken http_client_factory) that
    # happened AFTER the slot was already consumed left the cost ledger
    # permanently diverged from reality, with no artifact anywhere
    # documenting that consumption. The cost check must only run once we
    # know the request can actually be built.
    from shared.cost import CostService

    def _broken_factory():
        raise RuntimeError("broken factory — simulates a harness-internal config bug")

    cost_service = CostService(execution_id="exec_broken_factory", storage_dir=str(tmp_path / "cost"), cap=5)
    harness = EvidenceHarness(
        execution_id="exec_broken_factory",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path / "evidence"),
        http_client_factory=_broken_factory,
        cost_service=cost_service,
    )

    with pytest.raises(RuntimeError):
        harness.capture(_action(), role=ObservationRole.MAIN)

    assert cost_service.executed_action_count == 0  # never consumed — the failure was pre-send


def test_capture_does_not_consume_a_cost_slot_when_build_request_fails_before_send(tmp_path):
    # Same bug, the other failure point named in the review: a non-JSON-
    # serializable action.parameters makes client.build_request() itself
    # raise (a plain TypeError, not httpx.HTTPError/InvalidURL) — this must
    # also happen BEFORE the cost slot is consumed, not after.
    from shared.cost import CostService

    class _Unserializable:
        pass

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    cost_service = CostService(execution_id="exec_bad_json", storage_dir=str(tmp_path / "cost"), cap=5)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    harness = EvidenceHarness(
        execution_id="exec_bad_json",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path / "evidence"),
        http_client=client,
        cost_service=cost_service,
    )
    action = _action(method="POST", parameters={"bad": _Unserializable()})

    with pytest.raises(TypeError):
        harness.capture(action, role=ObservationRole.MAIN)

    assert cost_service.executed_action_count == 0


def test_capture_never_refuses_when_no_cost_service_is_given(tmp_path):
    # Default behavior (cost_service=None) is unchanged — every other test
    # in this file that doesn't pass cost_service relies on this too.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    harness = _harness(tmp_path, handler)
    for _ in range(5):
        observation = harness.capture(_action(), role=ObservationRole.MAIN)
        assert observation.access_result == AccessResult.GRANTED


def test_login_rejects_a_null_token_instead_of_building_a_broken_credential(tmp_path):
    # Real gap found via review: a token that resolves (path exists) but is
    # null/empty/non-string used to sail through silently, becoming a
    # literal broken credential (e.g. "Bearer None") sent on every later
    # request with no error anywhere.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"authentication": {"token": None}})

    harness = _harness_with_isolated_identities(tmp_path, handler)
    login_action = _action(
        method="POST", target="https://target.example.com/login", type=ActionType.TEST_DATA_CREATION
    )

    with pytest.raises(ValueError, match="rỗng hoặc không phải string"):
        harness.login("alice", login_action, token_json_path="authentication.token")

    client = harness._client_for("alice")
    assert client.headers.get("Authorization") != "Bearer None"


def test_login_redacts_only_the_known_path_when_the_null_token_check_fails(tmp_path):
    # Unlike the extraction-FAILURE case (whole body wiped, since we don't
    # know where the secret is), a null/invalid token DOES resolve to a
    # known path — only that path should be redacted, not the whole body.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"authentication": {"token": None, "other_field": "still-visible"}})

    harness = _harness_with_isolated_identities(tmp_path, handler)
    login_action = _action(
        method="POST", target="https://target.example.com/login", type=ActionType.TEST_DATA_CREATION
    )

    with pytest.raises(ValueError):
        harness.login("alice", login_action, token_json_path="authentication.token")

    artifact_files = [f for f in harness._storage_dir.glob("*.json") if f.name != "seed_manifest.json"]
    raw_text = artifact_files[0].read_text()
    assert "still-visible" in raw_text  # unrelated fields untouched


def test_marker_check_is_case_insensitive(tmp_path):
    # Real gap found via review: a target that reflects the marker back
    # with different casing used to be reported as marker-ABSENT — a false
    # negative that silently under-reports a real leak.
    marker = "abc123def456"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"leaked value: {marker.upper()}")

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN, marker=marker)
    assert observation.response_contains_marker is True


def test_capture_truncates_a_response_larger_than_the_size_cap(tmp_path):
    # Real gap found via review: no cap on response size at all, an
    # unbounded body risked an OOM crash on a single capture() call — a
    # worse instance of the "lose evidence to a crash" failure this module
    # otherwise guards against.
    huge_body = "x" * (_MAX_RESPONSE_BYTES + 1000)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=huge_body)

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN)

    raw = json.loads(Path(observation.raw_evidence_ref).read_text())
    assert raw["response"]["truncated"] is True
    assert len(raw["response"]["body"]) <= _MAX_RESPONSE_BYTES
    # Still classified normally from the status code even though the body
    # was truncated — truncation must not corrupt the mechanical
    # access_result bucketing.
    assert observation.access_result == AccessResult.GRANTED


def test_capture_stores_non_utf8_response_as_base64_with_encoding_label(tmp_path):
    # Real gap found via review: relying on a lossy text decode meant the
    # stored artifact wasn't actually byte-faithful to the real response
    # for binary/non-UTF8 bodies, undermining the Oracle's hash
    # re-verification (which only proves the artifact hasn't changed SINCE
    # capture, not that capture faithfully recorded the real wire bytes).
    binary_body = b"\xff\xfe\x00\x01binary-data-not-utf8"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=binary_body)

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN)

    raw = json.loads(Path(observation.raw_evidence_ref).read_text())
    assert raw["response"]["body_encoding"] == "base64"
    assert base64.b64decode(raw["response"]["body"]) == binary_body


def test_capture_stores_normal_utf8_response_as_plain_text_not_base64(tmp_path):
    # Confirms the common case (JSON/HTML/text bodies, the vast majority of
    # real responses) stays human-readable rather than needlessly
    # base64-encoding everything.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 42, "owner": "alice"})

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN)

    raw = json.loads(Path(observation.raw_evidence_ref).read_text())
    assert raw["response"]["body_encoding"] == "utf-8"
    assert json.loads(raw["response"]["body"]) == {"id": 42, "owner": "alice"}


# ----- Regression tests: bugs found by the review that verified the fixes
# above (finding the stale status_code, truncation losing everything,
# marker-vs-truncation, URL-redaction drift, and charset handling). -----


def test_capture_does_not_leak_a_stale_status_code_when_the_body_read_fails_midstream(tmp_path):
    # Real HIGH bug introduced by the streaming rewrite itself, found by a
    # 2nd review pass: splitting the read into "headers" then "body" stages
    # created a state (headers known, body read then failed) where a STALE
    # status_code leaked into the final observation even though
    # received_response stayed False and the artifact recorded only an
    # "error" key — producing a confident GRANTED/DENIED classification
    # from evidence that itself says the capture failed.
    class _BrokenStream(httpx.SyncByteStream):
        def __iter__(self):
            yield b"partial"
            raise httpx.RemoteProtocolError("connection reset mid-response")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=_BrokenStream())

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.POSITIVE_CONTROL)

    assert observation.status_code is None
    assert observation.access_result == AccessResult.AMBIGUOUS
    raw = json.loads(Path(observation.raw_evidence_ref).read_text())
    assert "response" not in raw
    assert raw["error"]["type"] == "RemoteProtocolError"


def test_capture_keeps_the_fitting_prefix_when_a_single_chunk_exceeds_the_cap(tmp_path):
    # Real HIGH bug found by a 2nd review pass: breaking out of the read
    # loop WITHOUT first keeping the part of the oversized chunk that still
    # fit meant a response delivered as one single big chunk (guaranteed
    # with httpx.MockTransport, i.e. every test in this suite, and plausible
    # for fast loopback targets) lost its ENTIRE body — 0 bytes stored —
    # while still merely labeled "truncated" rather than empty.
    huge_body = "x" * (_MAX_RESPONSE_BYTES + 1000)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=huge_body)

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN)

    raw = json.loads(Path(observation.raw_evidence_ref).read_text())
    assert raw["response"]["truncated"] is True
    assert len(raw["response"]["body"]) == _MAX_RESPONSE_BYTES  # kept the fitting prefix, not nothing
    assert raw["response"]["body"] == "x" * _MAX_RESPONSE_BYTES


def test_capture_reports_marker_as_uncertain_not_absent_when_response_is_truncated(tmp_path):
    # Real gap found by a 2nd review pass: a marker sitting past the
    # truncation cutoff used to come back as a confident "absent" —
    # indistinguishable from genuinely reading the whole body and not
    # finding it, a false negative for a real leak caused by the byte cap.
    marker = "sw-marker-past-the-cutoff"
    body = ("x" * (_MAX_RESPONSE_BYTES + 1000)) + marker  # marker sits AFTER the cutoff

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN, marker=marker)

    raw = json.loads(Path(observation.raw_evidence_ref).read_text())
    assert raw["response"]["truncated"] is True
    assert observation.response_contains_marker is None  # uncertain, NOT a confident False


def test_capture_still_reports_marker_found_even_if_response_was_truncated(tmp_path):
    # The other half of the fix above: a marker found WITHIN the part that
    # was actually read is still a real positive signal, not downgraded to
    # uncertain just because truncation happened elsewhere.
    marker = "sw-marker-before-the-cutoff"
    body = marker + ("x" * (_MAX_RESPONSE_BYTES + 1000))  # marker sits BEFORE the cutoff

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body)

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN, marker=marker)

    raw = json.loads(Path(observation.raw_evidence_ref).read_text())
    assert raw["response"]["truncated"] is True
    assert observation.response_contains_marker is True


def test_redact_url_query_leaves_url_byte_for_byte_unchanged_when_nothing_matches(tmp_path):
    # Real LOW gap found by a 2nd review pass: re-encoding via
    # urlencode(parse_qsl(...)) is not byte-exact (e.g. a bare flag with no
    # "=value" gains one) — must not touch the URL at all when no declared
    # sensitive key actually appears in it.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    harness = _harness(tmp_path, handler)
    action = _action(
        method="POST",
        type=ActionType.TEST_DATA_CREATION,
        target="https://target.example.com/path?flag&kept=c%20d",
    )
    observation = harness.capture(action, role=ObservationRole.MAIN, sensitive_body_keys={"token"})

    raw = json.loads(Path(observation.raw_evidence_ref).read_text())
    assert raw["request"]["url"] == "https://target.example.com/path?flag&kept=c%20d"


def test_capture_decodes_body_using_declared_charset_not_blind_utf8(tmp_path):
    # Real LOW/informational gap found by a 2nd review pass: a response
    # genuinely encoded as windows-1252 that HAPPENS to also be valid (but
    # WRONG) UTF-8 used to be silently misdecoded with no signal anything
    # was off — a regression from httpx's own charset-aware `.text`.
    text = "café"
    encoded = text.encode("windows-1252")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=encoded, headers={"Content-Type": "text/html; charset=windows-1252"}
        )

    harness = _harness(tmp_path, handler)
    observation = harness.capture(_action(), role=ObservationRole.MAIN)

    raw = json.loads(Path(observation.raw_evidence_ref).read_text())
    assert raw["response"]["body_encoding"] == "windows-1252"
    assert raw["response"]["body"] == text
