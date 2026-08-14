"""Predicate draft — weekly plan W5 (remaining item). DRAFT, not frozen
(freezing happens at Gate 3, W6, per the plan). Runs on
shared/models/observation.py's NormalizedObservation, which is itself an
unapproved draft — see that file's docstring for why. Pure code, no LLM
(SPEC §4.4: "Rule code thuần, không gọi LLM").
"""

from typing import Dict, List

from shared.models.observation import (
    AccessResult,
    NormalizedObservation,
    ObservationRole,
    PredicateResult,
    PredicateStatus,
)


def check_main_predicate(observation: NormalizedObservation) -> PredicateResult:
    """Group 1 (SPEC §4.4.1) — the condition that distinguishes "bug exists"
    from "bug doesn't exist". Only implemented for the blind-marker scenario
    (see shared/models/observation.py's docstring for scope limits): the
    marker must appear in the response AND must not have appeared in the
    outgoing request — otherwise it could just be the agent's own input
    reflected back, not real evidence the system's data store leaked it.
    """
    group = ObservationRole.MAIN.value
    if observation.role != ObservationRole.MAIN:
        return PredicateResult(
            group=group,
            status=PredicateStatus.INSUFFICIENT_DATA,
            reason=f"Observation has role={observation.role.value}, expected main.",
        )
    if observation.response_contains_marker is None or observation.request_contains_marker is None:
        return PredicateResult(
            group=group,
            status=PredicateStatus.INSUFFICIENT_DATA,
            reason="Missing marker data (response_contains_marker/request_contains_marker) to evaluate.",
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
    group = ObservationRole.POSITIVE_CONTROL.value
    if observation.role != ObservationRole.POSITIVE_CONTROL:
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
    group = ObservationRole.DENIED_CONTROL.value
    if observation.role != ObservationRole.DENIED_CONTROL:
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

    results = []
    for role, check_fn in _CHECKS:
        matches = by_role.get(role, [])
        if not matches:
            results.append(
                PredicateResult(
                    group=role.value,
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
                    group=role.value,
                    status=PredicateStatus.INSUFFICIENT_DATA,
                    reason=f"{len(matches)} observations found for role={role.value}, expected exactly 1 — "
                    "ambiguous, cannot pick one automatically without discarding evidence.",
                )
            )
        else:
            results.append(check_fn(matches[0]))
    return results
