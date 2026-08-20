"""Predicate draft — weekly plan W5 (remaining item). DRAFT, not frozen
(freezing happens at Gate 3, W6, per the plan). Runs on
shared/models/observation.py's NormalizedObservation, which is itself an
unapproved draft — see that file's docstring for why. Pure code, no LLM
(SPEC §4.4: "Rule code thuần, không gọi LLM").
"""

import hashlib
from pathlib import Path
from typing import Dict, List, Optional

from shared.models.observation import (
    AccessResult,
    NormalizedObservation,
    ObservationRole,
    PredicateResult,
    PredicateStatus,
)

# SPEC §4.4.3: "Tập predicate của một kịch bản có version, ghi vào package.
# Khi rule thay đổi, package cũ không bị đánh giá lại âm thầm." Recorded into
# the Verification Package's "Oracle rule / version" field (§7, field #13).
# "v1-draft" because this predicate set itself is an explicit DRAFT
# (see this module's own docstring) — freezing happens at Gate 3, not yet
# reached (still Chặng 1). Bump this string any time the logic in
# check_main_predicate/check_positive_control/check_denied_control/
# evaluate_predicates changes in any way that could affect a verdict for
# the SAME evidence, so an old package's version honestly reflects what
# rule set actually produced it.
# v2-draft (2026-08-20): check_main_predicate gained a 2nd, independent way
# to reach SATISFIED — same-resource cross-identity access (see its own
# docstring) — for resources with no free-text field to plant a blind
# marker in. Old packages built under v1-draft are unaffected (this only
# ADDS a way to satisfy main, never removes the marker path or changes its
# behavior).
PREDICATE_RULE_VERSION = "v2-draft"


def _hash_mismatch_reason(observation: NormalizedObservation) -> Optional[str]:
    """SPEC §6.4 control #8: "Hash không khớp thì không được CONFIRMED" — no
    exceptions in MVP. Returns None if the on-disk artifact's bytes still
    hash to `observation.raw_evidence_hash`, or a reason string if not (or
    if the file can't even be read — an unreadable/missing artifact is at
    least as bad as a mismatched one, never treated as "assume it's fine").
    Called from evaluate_predicates() before a group's role-specific check
    runs, so a failure here surfaces as INSUFFICIENT_DATA rather than
    letting a tampered artifact sail through unnoticed.

    Catches ValueError alongside OSError — a `raw_evidence_ref` containing
    an embedded NUL byte (a corrupted or adversarially-crafted stored
    observation, not something the current EvidenceHarness ever produces
    itself, but this project's own hash-check exists precisely because
    stored evidence must be treated as possibly tampered) makes
    `Path.read_bytes()` raise `ValueError`, not `OSError`.
    """
    try:
        raw_bytes = Path(observation.raw_evidence_ref).read_bytes()
    except (OSError, ValueError) as exc:
        return f"Không đọc được raw evidence tại '{observation.raw_evidence_ref}': {exc}"
    recomputed = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
    if recomputed != observation.raw_evidence_hash:
        return (
            f"Hash không khớp (SPEC §6.4 control #8) — lưu trong observation là "
            f"'{observation.raw_evidence_hash}', tính lại từ file thật trên đĩa là '{recomputed}'."
        )
    return None


def _check_same_resource_cross_identity(
    main_observation: NormalizedObservation, positive_control_observation: Optional[NormalizedObservation]
) -> Optional[PredicateResult]:
    """2nd, independent way for the main predicate to reach SATISFIED —
    added because a blind marker can't be planted everywhere (SPEC §4.3.4's
    mechanism needs a free-text field to hide the marker in; a resource
    whose only writable field is a business-rule-constrained integer, e.g.
    an order `quantity` capped at 5, has nowhere to put a 32-char random
    token) — the exact shape of a real leak against OWASP Juice Shop's
    basket IDOR, where an identity that never owned the basket read back
    the exact item the owner had just added, yet check_main_predicate
    could only ever report insufficient_data for it.

    Deliberately does NOT try to be a general "do these 2 responses share
    content" check — that would need to reason about how much
    coincidental overlap is meaningful, which is exactly the kind of
    heuristic guess this project's redaction/marker design elsewhere
    always refuses to make (see shared/policy.py's own "no heuristic
    redaction" principle). Reasons purely from STRUCTURE instead, which
    needs no judgment call about content at all: main and positive_control
    hit the literal same resolved URL, both got a real response the target
    itself classified as GRANTED, and — the actual boundary being tested —
    they did it as 2 DIFFERENT identities. That combination is exactly what
    "someone who isn't the owner could read the owner's data" means,
    independent of what the response body says.

    Returns None (never a verdict-bearing result on its own) whenever the
    comparison isn't safely applicable — no positive_control observation to
    compare against, either side's resolved_target unknown (observations
    captured before that field existed), a same-identity comparison (would
    just mean the owner read their own data twice, proving nothing about an
    access-control boundary — same reasoning evaluate_predicates() already
    applies to the OTHER 2 groups), a hash mismatch on either side (an
    observation already flagged as possibly tampered can't be trusted to
    vouch for a 2nd one), or the two hitting different resources (this
    check has nothing to say about 2 unrelated URLs). The caller falls
    back to the ordinary "insufficient data" outcome in every such case,
    exactly as if this function didn't exist — it can only ever ADD a way
    to reach SATISFIED, never invent a false one from missing information.
    """
    if positive_control_observation is None:
        return None
    if main_observation.resolved_target is None or positive_control_observation.resolved_target is None:
        return None
    if main_observation.resolved_target != positive_control_observation.resolved_target:
        return None
    if main_observation.identity == positive_control_observation.identity:
        return None
    if main_observation.access_result != AccessResult.GRANTED:
        return None
    if positive_control_observation.access_result != AccessResult.GRANTED:
        return None
    if _hash_mismatch_reason(main_observation) is not None:
        return None
    if _hash_mismatch_reason(positive_control_observation) is not None:
        return None
    return PredicateResult(
        group=ObservationRole.MAIN,
        status=PredicateStatus.SATISFIED,
        reason=(
            f"No blind marker was used, but main (identity='{main_observation.identity}') and "
            f"positive_control (identity='{positive_control_observation.identity}') both successfully "
            f"(access_result=granted) read the EXACT SAME resource "
            f"('{main_observation.resolved_target}') as 2 different, non-colliding identities — the "
            "suspected behavior reproduced without needing planted bait data."
        ),
    )


def check_main_predicate(
    observation: NormalizedObservation,
    positive_control_observation: Optional[NormalizedObservation] = None,
) -> PredicateResult:
    """Group 1 (SPEC §4.4.1) — the condition that distinguishes "bug exists"
    from "bug doesn't exist". 2 independent ways to reach SATISFIED:

    1. The blind-marker scenario (SPEC §4.3.4, checked first): the marker
       must appear in the response AND must not have appeared in the
       outgoing request — otherwise it could just be the agent's own input
       reflected back, not real evidence the system's data store leaked it.
    2. Same-resource cross-identity access (see
       _check_same_resource_cross_identity's own docstring) — tried ONLY
       when this observation has no marker data at all (the scenario never
       used one). If a marker WAS used and explicitly came back
       unsatisfied, that explicit negative result stands — a structural
       coincidence is never allowed to override a marker check the
       operator deliberately ran and got a real answer from.
    """
    group = ObservationRole.MAIN
    if observation.role != group:
        return PredicateResult(
            group=group,
            status=PredicateStatus.INSUFFICIENT_DATA,
            reason=f"Observation has role={observation.role.value}, expected main.",
        )
    if observation.response_contains_marker is None or observation.request_contains_marker is None:
        same_resource_result = _check_same_resource_cross_identity(observation, positive_control_observation)
        if same_resource_result is not None:
            return same_resource_result
        return PredicateResult(
            group=group,
            status=PredicateStatus.INSUFFICIENT_DATA,
            reason="Missing marker data (response_contains_marker/request_contains_marker) to evaluate, and "
            "the same-resource cross-identity check either found no comparable positive_control observation "
            "or the 2 observations don't structurally show a cross-identity read of the same resource.",
        )
    if observation.response_contains_marker and not observation.request_contains_marker:
        return PredicateResult(
            group=group,
            status=PredicateStatus.SATISFIED,
            reason="Marker appeared in the response and was absent from the request — the suspected behavior reproduced.",
        )
    return PredicateResult(
        group=group,
        status=PredicateStatus.UNSATISFIED,
        reason="Marker did not appear in the response, or was already present in the request (not proof of a leak).",
    )


def check_positive_control(observation: NormalizedObservation) -> PredicateResult:
    """Group 2 (SPEC §4.4.1) — proves the bait data and observation channel
    work normally: the correct (owning) identity MUST be able to read it.
    SPEC: "Quy tắc không có ngoại lệ: thiếu positive control thì không có
    CONFIRMED" — this predicate failing to satisfy blocks CONFIRMED
    regardless of what the main predicate says.
    """
    group = ObservationRole.POSITIVE_CONTROL
    if observation.role != group:
        return PredicateResult(
            group=group,
            status=PredicateStatus.INSUFFICIENT_DATA,
            reason=f"Observation has role={observation.role.value}, expected positive_control.",
        )
    if observation.access_result == AccessResult.GRANTED:
        return PredicateResult(
            group=group,
            status=PredicateStatus.SATISFIED,
            reason="The owning identity could read the data as expected — the observation channel works.",
        )
    if observation.access_result == AccessResult.DENIED:
        return PredicateResult(
            group=group,
            status=PredicateStatus.UNSATISFIED,
            reason="The owning identity could NOT read the data — cannot tell 'the system correctly blocked access' "
            "from 'the bait data doesn't exist / the capture channel is broken'.",
        )
    return PredicateResult(
        group=group,
        status=PredicateStatus.INSUFFICIENT_DATA,
        reason="access_result is ambiguous (unexpected status/response shape) — cannot tell if the owning "
        "identity's read succeeded.",
    )


def check_denied_control(observation: NormalizedObservation) -> PredicateResult:
    """Group 3 (SPEC §4.4.1) — the reverse test: an identity that definitely
    has no permission MUST be denied. Guards against the system returning
    data to everyone for an unrelated reason (e.g. an unexpectedly public
    endpoint), which would otherwise look identical to a real leak.
    """
    group = ObservationRole.DENIED_CONTROL
    if observation.role != group:
        return PredicateResult(
            group=group,
            status=PredicateStatus.INSUFFICIENT_DATA,
            reason=f"Observation has role={observation.role.value}, expected denied_control.",
        )
    if observation.access_result == AccessResult.DENIED:
        return PredicateResult(
            group=group,
            status=PredicateStatus.SATISFIED,
            reason="The unauthorized identity was correctly denied.",
        )
    if observation.access_result == AccessResult.GRANTED:
        return PredicateResult(
            group=group,
            status=PredicateStatus.UNSATISFIED,
            reason="The unauthorized identity could still read the data — the system may be returning it to "
            "everyone for an unrelated reason (e.g. an unexpectedly public endpoint).",
        )
    return PredicateResult(
        group=group,
        status=PredicateStatus.INSUFFICIENT_DATA,
        reason="access_result is ambiguous (unexpected status/response shape) — cannot tell if the unauthorized "
        "identity was actually denied.",
    )


_CHECKS = (
    (ObservationRole.MAIN, check_main_predicate),
    (ObservationRole.POSITIVE_CONTROL, check_positive_control),
    (ObservationRole.DENIED_CONTROL, check_denied_control),
)


def evaluate_predicates(observations: List[NormalizedObservation]) -> List[PredicateResult]:
    """Runs all 3 required predicate groups (SPEC §4.4.1: "Cả ba nhóm đều
    phải có kết quả trong package") over one run's observations. If an
    observation for a given role is missing entirely, that group still gets
    a result — INSUFFICIENT_DATA with a clear reason — never silently
    skipped.
    """
    by_role: Dict[ObservationRole, List[NormalizedObservation]] = {}
    for observation in observations:
        by_role.setdefault(observation.role, []).append(observation)

    results: List[Optional[PredicateResult]] = []
    single_observation_by_role: Dict[ObservationRole, NormalizedObservation] = {}
    for role, _check_fn in _CHECKS:
        matches = by_role.get(role, [])
        if not matches:
            results.append(
                PredicateResult(
                    group=role,
                    status=PredicateStatus.INSUFFICIENT_DATA,
                    reason=f"No observation was captured for role={role.value}.",
                )
            )
        elif len(matches) > 1:
            # Silently picking one (e.g. "last wins") would make the result
            # depend on list order and could discard evidence that actually
            # satisfied the predicate — a direct violation of SPEC P2
            # ("bằng chứng trước, phát biểu sau"). A well-formed plan should
            # never produce more than 1 observation per role; if it does,
            # that's an anomaly to surface, not resolve silently.
            results.append(
                PredicateResult(
                    group=role,
                    status=PredicateStatus.INSUFFICIENT_DATA,
                    reason=f"{len(matches)} observations found for role={role.value}, expected exactly 1 — "
                    "ambiguous, cannot pick one automatically without discarding evidence.",
                )
            )
        else:
            results.append(None)  # placeholder — filled in below, once identity collisions are known
            single_observation_by_role[role] = matches[0]

    # positive_control must use a genuinely DIFFERENT identity from the
    # other 2 roles. SPEC §4.4.1: positive_control's whole point is "đúng
    # identity phải đọc được" (the LEGITIMATE owner) as the contrasting
    # case to main's suspected-unauthorized read and denied_control's
    # confirmed-unauthorized read — if positive_control used the SAME
    # identity as main, "main" satisfied would just mean the owner read
    # their own data (not evidence of any access-control boundary being
    # crossed at all); if positive_control used the SAME identity as
    # denied_control, that one identity can't coherently be BOTH
    # "correctly allowed" and "correctly denied" for a meaningful test.
    # Nothing about the blind-marker check itself (request/response marker
    # presence) can detect this — it's purely an identity-bookkeeping fact
    # the check functions never see. An operator forgetting a
    # `--role-identity` mapping (cli.py) — falling back to the single
    # shared --identity for every role — is a realistic, not just
    # theoretical, way to reach this silently.
    #
    # main and denied_control are DELIBERATELY NOT compared against each
    # other here: a valid scenario design can reuse the SAME identity for
    # both — e.g. the attacker identity under test in `main` (unauthorized
    # access to the resource under test) also serving as `denied_control`
    # against a DIFFERENT, unrelated resource (proving the system isn't
    # simply wide open to that identity everywhere, just broken for this
    # one resource). Only positive_control's identity is structurally
    # required to be unique.
    colliding_roles: set = set()
    role_pairs = [
        (ObservationRole.MAIN, ObservationRole.POSITIVE_CONTROL),
        (ObservationRole.POSITIVE_CONTROL, ObservationRole.DENIED_CONTROL),
    ]
    for role_a, role_b in role_pairs:
        obs_a = single_observation_by_role.get(role_a)
        obs_b = single_observation_by_role.get(role_b)
        if obs_a is not None and obs_b is not None and obs_a.identity == obs_b.identity:
            colliding_roles.add(role_a)
            colliding_roles.add(role_b)

    for i, (role, check_fn) in enumerate(_CHECKS):
        if results[i] is not None:
            continue  # missing/ambiguous placeholder from the first pass — already final
        observation = single_observation_by_role[role]
        if role in colliding_roles:
            results[i] = PredicateResult(
                group=role,
                status=PredicateStatus.INSUFFICIENT_DATA,
                reason=f"identity='{observation.identity}' is the SAME identity used for another required "
                "role in this run — cannot prove an access-control boundary when 2 roles that must "
                "represent different identities collapse into 1.",
            )
            continue
        hash_problem = _hash_mismatch_reason(observation)
        if hash_problem is not None:
            results[i] = PredicateResult(group=role, status=PredicateStatus.INSUFFICIENT_DATA, reason=hash_problem)
        elif role == ObservationRole.MAIN:
            # The only check_fn that ever needs a 2nd observation — see
            # check_main_predicate/_check_same_resource_cross_identity.
            # single_observation_by_role.get(...) is None whenever
            # positive_control has 0 or >1 observations (missing or
            # ambiguous, per the first pass above) — check_main_predicate
            # already treats a None here as "can't use this path".
            results[i] = check_fn(observation, single_observation_by_role.get(ObservationRole.POSITIVE_CONTROL))
        else:
            results[i] = check_fn(observation)
    return results
