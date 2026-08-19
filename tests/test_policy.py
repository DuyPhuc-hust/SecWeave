from datetime import datetime, timedelta, timezone

import pytest

from shared.models.action import ActionSpec, ActionType
from shared.policy import is_allowed
from tests.factories import sample_authorization

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=timezone.utc)

ALLOWED_ENTRY = "GET https://staging.example.com/api/objects/{id}"


def _action(**overrides) -> ActionSpec:
    defaults = dict(
        type=ActionType.READ_ONLY,
        method="GET",
        target="https://staging.example.com/api/objects/42",
        description="Read object 42 as a non-owner identity.",
    )
    defaults.update(overrides)
    return ActionSpec(**defaults)


def test_matching_action_is_allowed():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is True
    assert ALLOWED_ENTRY in decision.reason


def test_wrong_method_is_denied():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(method="POST", type=ActionType.TEST_DATA_CREATION)
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_endpoint_outside_allowlist_is_denied():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(target="https://staging.example.com/api/admin/users")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False
    assert "không khớp" in decision.reason


def test_same_path_on_different_host_is_denied():
    # Regression for a fixed vulnerability: Policy Service used to compare
    # path only, ignoring host — an action targeting any host (including one
    # controlled by an attacker) would still "match" the allowlist as long
    # as the path had the right shape. Right path, wrong host MUST be denied.
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(target="https://evil-attacker-controlled.com/api/objects/42")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_same_path_different_scheme_is_denied():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(target="http://staging.example.com/api/objects/42")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_scheme_comparison_is_case_insensitive():
    # Real nitpick found via independent review: URL schemes are case-
    # insensitive per RFC 3986, but this compared them case-sensitively
    # while netloc was already lowercased — a legitimate "HTTPS://..."
    # action used to be wrongly DENIED (fails safe, not a bypass, but a
    # real inconsistency worth fixing).
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(target="HTTPS://staging.example.com/api/objects/42")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is True


def test_allowlist_entry_missing_host_never_matches():
    # A misconfigured entry (missing host, the old path-only shape) must be
    # denied outright, not silently fall back to matching path only — that's
    # exactly the vulnerability that was fixed.
    authorization = sample_authorization(allowed_actions=["GET /api/objects/{id}"])
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is False


def test_allowlist_entry_tolerates_extra_whitespace_between_method_and_url():
    # A typo'd double space must still match correctly — urlsplit() used to
    # treat the extra whitespace as part of the path, leaving netloc empty
    # and always denying the match even though the allowlist "looks right"
    # to the eye.
    authorization = sample_authorization(allowed_actions=["GET  https://staging.example.com/api/objects/{id}"])
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is True


def test_action_with_unexpected_parameters_is_denied_even_if_url_matches():
    # Real gap found via full-codebase review: an allowlist entry with no
    # params clause used to say nothing about ActionSpec.parameters at all —
    # an action matching the URL/method was approved regardless of what was
    # in its (LLM-authored, unvalidated) body/query. An entry with no params
    # clause must mean "parameters must be empty", not "anything goes".
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(parameters={"debug_bypass_auth": "1", "impersonate": "admin"})
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_action_with_empty_parameters_still_matches_entry_without_params_clause():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    decision = is_allowed(_action(parameters={}), authorization, now=NOW)
    assert decision.allowed is True


def test_action_parameters_allowed_when_keys_match_params_clause():
    authorization = sample_authorization(
        allowed_actions=["POST https://staging.example.com/api/basket params:username,password"]
    )
    action = _action(
        method="POST",
        type=ActionType.TEST_DATA_CREATION,
        target="https://staging.example.com/api/basket",
        parameters={"username": "tester", "password": "secret"},
    )
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is True


def test_action_parameter_key_outside_params_clause_is_denied():
    authorization = sample_authorization(
        allowed_actions=["POST https://staging.example.com/api/basket params:username,password"]
    )
    action = _action(
        method="POST",
        type=ActionType.TEST_DATA_CREATION,
        target="https://staging.example.com/api/basket",
        parameters={"username": "tester", "password": "secret", "role": "admin"},
    )
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_action_with_no_parameters_still_matches_entry_that_has_a_params_clause():
    # An entry permitting some keys doesn't REQUIRE them to be present.
    authorization = sample_authorization(
        allowed_actions=["POST https://staging.example.com/api/basket params:username,password"]
    )
    action = _action(
        method="POST",
        type=ActionType.TEST_DATA_CREATION,
        target="https://staging.example.com/api/basket",
        parameters={},
    )
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is True


def test_action_parameter_value_matching_declared_pattern_is_allowed():
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id} params:userId=^[0-9]+$"]
    )
    action = _action(parameters={"userId": "42"})
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is True


def test_action_parameter_value_not_matching_declared_pattern_is_denied():
    # The real gap this closes: checking only the parameter NAME let ANY
    # value through for an already-allowed key. userId is on the allowlist,
    # but its value here isn't the caller's own id — a name-only allowlist
    # entry would have let this through.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id} params:userId=^[0-9]+$"]
    )
    action = _action(parameters={"userId": "42 OR 1=1"})
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_action_parameter_key_without_pattern_still_allows_any_value():
    # Backward compatibility: a bare key (no "=regex") keeps the previous,
    # name-only behaviour — existing allowlist strings written before this
    # feature existed must keep working exactly as before.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id} params:userId"]
    )
    action = _action(parameters={"userId": "anything at all, no pattern declared"})
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is True


def test_action_missing_a_pattern_constrained_parameter_is_still_allowed():
    # A declared pattern constrains the value IF the key is present — it
    # does not make the key mandatory (matches the no-params-required
    # behaviour already established for name-only keys).
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id} params:userId=^[0-9]+$"]
    )
    action = _action(parameters={})
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is True


def test_malformed_value_pattern_denies_outright():
    # An invalid regex after "=" is a misconfiguration — fail safe (deny),
    # same philosophy as test_malformed_params_clause_denies_outright.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id} params:userId=(unclosed"]
    )
    decision = is_allowed(_action(parameters={"userId": "42"}), authorization, now=NOW)
    assert decision.allowed is False


def test_empty_pattern_after_equals_denies_outright():
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id} params:userId="]
    )
    decision = is_allowed(_action(parameters={"userId": "42"}), authorization, now=NOW)
    assert decision.allowed is False


def test_bounded_repetition_quantifier_in_value_pattern_is_not_mangled():
    # Real bug found via independent review: a naive comma-split cut
    # "^[0-9]{1,10}$" (the single most natural regex for "N-digit id") into
    # "^[0-9]{1" (a near-useless truncated pattern that compiles without
    # error) plus a bogus extra allowlist key "10}$" mapped to "any value
    # allowed" — corrupting the allowlist silently, no error surfaced.
    authorization = sample_authorization(
        allowed_actions=[
            "GET https://staging.example.com/api/objects/{id} params:userId=^[0-9]{1,10}$"
        ]
    )
    matching = _action(parameters={"userId": "42"})
    assert is_allowed(matching, authorization, now=NOW).allowed is True

    too_long = _action(parameters={"userId": "12345678901"})
    assert is_allowed(too_long, authorization, now=NOW).allowed is False

    # The bogus leftover key from the old bug ("10}$") must not exist as a
    # separately-allowed, unconstrained parameter.
    smuggled = _action(parameters={"10}$": "anything"})
    assert is_allowed(smuggled, authorization, now=NOW).allowed is False


def test_null_parameter_value_never_satisfies_a_declared_pattern():
    # str(None) == "None" can satisfy a permissive-looking pattern like
    # "^[A-Za-z]+$" — an operator declaring a value pattern for a string
    # field would not expect a JSON null to pass it. A declared pattern is
    # a promise of real data of a specific shape; null must always fail it,
    # regardless of how permissive the pattern text is.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id} params:userId=^[A-Za-z]+$"]
    )
    decision = is_allowed(_action(parameters={"userId": None}), authorization, now=NOW)
    assert decision.allowed is False


def test_percent_encoded_traversal_segment_is_denied():
    # HIGH severity real bug found via independent review: matching the RAW
    # (still percent-encoded) path let "%2e%2e%2fadmin" satisfy a "{id}"
    # placeholder's [^/]+ regex (no literal "/" in the raw text) — but
    # httpx sends the raw encoded path unchanged on the wire, and the real
    # target/any proxy in front of it may decode+normalize it into
    # ".../api/objects/../admin" -> ".../api/admin", escaping the
    # allowlisted scope entirely (same bypass class as the host-escape bug
    # this module's docstring already calls "equivalent to SSRF", just via
    # the path instead of the host).
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id}"]
    )
    action = _action(target="https://staging.example.com/api/objects/%2e%2e%2fadmin")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_percent_encoded_slash_inside_an_id_segment_is_denied():
    # A "%2f" inside what's supposed to be a single {id} segment decodes to
    # a literal "/" — changing the path's real segment structure from what
    # the raw-text regex match saw. Must be denied, not silently matched.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id}"]
    )
    action = _action(target="https://staging.example.com/api/objects/foo%2fbar")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_percent_encoded_but_harmless_id_segment_is_still_allowed():
    # The fix must not deny ordinary percent-encoded characters that decode
    # to something harmless and still fit in a single path segment (e.g. an
    # "@" in an email-shaped id) — only "/" and "."/".." segments are denied.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id}"]
    )
    action = _action(target="https://staging.example.com/api/objects/us%40er")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is True


def test_double_percent_encoded_traversal_segment_is_denied():
    # Real bypass found via a second independent review of the fix above:
    # single-pass unquote() only turns "%252e%252e%252fadmin" into
    # "%2e%2e%2fadmin" — still not a literal "." /".." /"/" — so the
    # original fix let a DOUBLE-encoded traversal segment straight through.
    # A backend that decodes twice (a documented, real technique against
    # old IIS/nginx configs, many WAFs, and some app frameworks) would
    # still normalize this into an out-of-scope path.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id}"]
    )
    action = _action(target="https://staging.example.com/api/objects/%252e%252e%252Fadmin")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_backslash_traversal_segment_is_denied():
    # Real bypass found via the same second review: "..%5cadmin" decodes to
    # "..\\admin" — not "/"-delimited (so the slash-count guard stays
    # silent) and not literally ".." either (so the segment-equality check
    # missed it too). A Windows/IIS-style backend treats "\\" as a path
    # separator, so this is the same traversal class via a different
    # separator character.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id}"]
    )
    action = _action(target="https://staging.example.com/api/objects/..%5cadmin")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_double_percent_encoded_but_harmless_id_segment_is_still_allowed():
    # The multi-pass decode must not deny an ordinary double-encoded
    # harmless character either.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id}"]
    )
    action = _action(target="https://staging.example.com/api/objects/us%2540er")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is True


def test_unicode_fullwidth_solidus_traversal_segment_is_denied():
    # Real bypass found via independent review: U+FF0F FULLWIDTH SOLIDUS
    # ("／") contains no literal ASCII "/"/"."/"\\", so the existing checks
    # (slash-count, backslash, dot-segment) all pass it through unchanged
    # as one opaque {id}-style segment — but IIS/ASP.NET's "best-fit"
    # mapping and any NFKC-normalizing backend collapse it back to a
    # literal "/" before routing, so "1／..／admin" would actually reach the
    # target as "1/../admin", exactly the scope-escape this function exists
    # to prevent for the ASCII-encoding variants above.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id}"]
    )
    action = _action(target="https://staging.example.com/api/objects/1／..／admin")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_ordinary_unicode_segment_that_does_not_normalize_into_a_separator_is_still_allowed():
    # The NFKC-based lookalike-separator check must not deny an ordinary
    # non-ASCII path segment that has nothing to do with a separator —
    # e.g. a real full-width digit, which NFKC-normalizes to a plain ASCII
    # digit but never introduces a new "/"/"."/"\\".
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id}"]
    )
    action = _action(target="https://staging.example.com/api/objects/１２３")  # "123" full-width
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is True


def test_action_with_query_string_smuggled_directly_in_target_is_denied():
    # Real bypass found via review: the parameters-check above only looks at
    # ActionSpec.parameters — a query string embedded directly in
    # action.target (e.g. "...?debug_bypass_auth=1") bypassed it entirely,
    # since evidence_harness/harness.py sends the target URL's own query
    # string to the real target unfiltered when params=None.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id} params:id"]
    )
    action = _action(
        target="https://staging.example.com/api/objects/42?debug_bypass_auth=1&admin=true",
        parameters={},
    )
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_malformed_params_clause_denies_outright():
    # A 3rd token that isn't a well-formed "params:..." clause is a
    # misconfiguration — fail safe (deny), never guess an interpretation.
    authorization = sample_authorization(
        allowed_actions=["GET https://staging.example.com/api/objects/{id} not-a-params-clause"]
    )
    decision = is_allowed(_action(parameters={}), authorization, now=NOW)
    assert decision.allowed is False


@pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH", "delete", "put"])
def test_destructive_methods_are_always_denied_regardless_of_allowlist(method):
    # The allowlist "allows" this endpoint for any method — but a
    # destructive method must still be hard-blocked; a misconfigured
    # allowlist can't unlock it either.
    authorization = sample_authorization(
        allowed_actions=[f"{method.upper()} https://staging.example.com/api/objects/{{id}}"]
    )
    action = _action(method=method, type=ActionType.TEST_DATA_CREATION)
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False
    assert "không bao giờ được phép" in decision.reason


def test_revoked_authorization_is_denied():
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY], revoked=True)
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is False
    assert "thu hồi" in decision.reason


def test_expired_authorization_is_denied():
    authorization = sample_authorization(
        allowed_actions=[ALLOWED_ENTRY], expiry=NOW - timedelta(days=1)
    )
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is False
    assert "hết hạn" in decision.reason


def test_action_before_window_start_is_denied():
    authorization = sample_authorization(
        allowed_actions=[ALLOWED_ENTRY], window_start=NOW + timedelta(hours=1)
    )
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is False
    assert "Chưa tới cửa sổ" in decision.reason


def test_action_after_window_end_is_denied():
    authorization = sample_authorization(
        allowed_actions=[ALLOWED_ENTRY], window_end=NOW - timedelta(hours=1)
    )
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is False
    assert "Đã qua cửa sổ" in decision.reason


def test_action_within_window_is_allowed():
    authorization = sample_authorization(
        allowed_actions=[ALLOWED_ENTRY],
        window_start=NOW - timedelta(hours=1),
        window_end=NOW + timedelta(hours=1),
    )
    decision = is_allowed(_action(), authorization, now=NOW)
    assert decision.allowed is True


def test_path_template_does_not_match_across_extra_segments():
    # "/api/objects/{id}" must match exactly 1 segment — must not match
    # "/api/objects/42/secret" (path traversal beyond the allowlist's intent).
    authorization = sample_authorization(allowed_actions=[ALLOWED_ENTRY])
    action = _action(target="https://staging.example.com/api/objects/42/secret")
    decision = is_allowed(action, authorization, now=NOW)
    assert decision.allowed is False


def test_matches_correct_entry_among_multiple_allowed_actions():
    authorization = sample_authorization(
        allowed_actions=[ALLOWED_ENTRY, "POST https://staging.example.com/api/objects"]
    )
    decision = is_allowed(
        _action(
            method="POST",
            type=ActionType.TEST_DATA_CREATION,
            target="https://staging.example.com/api/objects",
        ),
        authorization,
        now=NOW,
    )
    assert decision.allowed is True
    assert "POST https://staging.example.com/api/objects" in decision.reason
