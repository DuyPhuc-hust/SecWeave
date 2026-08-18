"""Assembles a VerificationPackage (SPEC §7) from one run's real artifacts.
Deliberately does NOT accept a pre-computed verdict/predicate_results as
separate parameters — it calls verdict_oracle.oracle.decide() itself on
the SAME `observations` list used for every other evidence-derived field,
so there is no way for the package's verdict to have been computed from a
DIFFERENT observation set than what the package itself claims to contain
(a real class of "two sources of truth can silently drift" bug this
project has fixed more than once elsewhere — e.g. PlanReviewResult
combining plan_check/cost_check instead of trusting a separately-passed
`approved` bool).

Scope: does NOT build SPEC §4.5's alternate "execution record" artifact
(see the empty-observations check below for that case). A partial run
(at least 1 real observation) still succeeds — decide() never raises for
an incomplete-but-non-empty set, just returns an unhelpful verdict.
"""

from typing import List

from shared.id_generator import generate_id
from shared.models.action import ActionSpec
from shared.models.entities import Authorization
from shared.models.kill_switch import ExecutionStatus
from shared.models.observation import NormalizedObservation
from shared.models.verification_package import Environment, VerificationPackage
from verdict_oracle.oracle import decide
from verdict_oracle.predicates import PREDICATE_RULE_VERSION


def assemble_verification_package(
    *,
    target_id: str,
    environment: Environment,
    revision: str,
    authorization: Authorization,
    scenario: str,
    execution_id: str,
    actions: List[ActionSpec],
    observations: List[NormalizedObservation],
    execution_status: ExecutionStatus,
    limitations: str,
    next_action: str,
) -> VerificationPackage:
    """`actions` should be every ActionSpec the plan made available (e.g.
    ActionPlan.actions) — NOT filtered down beforehand. `action_record`
    below keeps only the ones that actually produced an observation (via
    action_id == some observation's action_ref), so a package never claims
    an action was part of "what happened" when it was merely planned but
    never executed (e.g. a run stopped mid-plan by the kill-switch).

    `observations` should include EVERY observation from this execution —
    SETUP-role ones (logins, marker seeding) too, not just the 3 predicate-
    eligible roles — both because SPEC field #9 ("Action record: đủ để
    lặp lại") needs setup actions to actually be reproducible, and because
    evaluate_predicates() (called inside decide() below) already correctly
    ignores SETUP observations on its own, so passing the full list here
    costs nothing and loses no evidence from the package.

    Raises ValueError immediately for `observations=[]` — real gap found
    via independent review: this used to fall through to a generic,
    confusing pydantic ValidationError naming 5 unrelated fields
    (identities/action_record/raw_evidence_references/artifact_hashes/
    normalized_observations all failing min_length=1 at once) instead of
    one clear message naming the actual problem. A completely empty run
    (e.g. the kill-switch stopped everything before any evidence was ever
    captured) is exactly SPEC §4.5's "execution record" case this module
    doesn't build — better to fail loud and specific here than let a
    caller puzzle out 5 field errors that all trace back to one root cause.
    """
    if not observations:
        raise ValueError(
            "assemble_verification_package(): observations rỗng — không thể tạo Verification Package "
            "khi execution chưa thu được bất kỳ bằng chứng nào (đây là trường hợp SPEC §4.5 gọi là "
            "'execution record', chưa có code hỗ trợ ở increment này)."
        )

    verdict_result = decide(observations, execution_status=execution_status)

    executed_action_ids = {observation.action_ref for observation in observations}
    action_record = [action for action in actions if action.action_id in executed_action_ids]

    # Derived from what was ACTUALLY captured, not separately claimed by a
    # caller — a caller-supplied identity list could silently drift from
    # what the observations themselves record.
    identities = sorted({observation.identity for observation in observations})

    return VerificationPackage(
        package_id=generate_id("pkg"),
        target_id=target_id,
        environment=environment,
        revision=revision,
        authorization_reference=authorization.id,
        scenario=scenario,
        identities=identities,
        execution_id=execution_id,
        action_record=action_record,
        raw_evidence_references=[observation.raw_evidence_ref for observation in observations],
        artifact_hashes=[observation.raw_evidence_hash for observation in observations],
        normalized_observations=list(observations),
        oracle_rule_version=PREDICATE_RULE_VERSION,
        predicate_results=verdict_result.predicate_results,
        verdict=verdict_result.verdict,
        verdict_reason=verdict_result.reason,
        limitations=limitations,
        next_action=next_action,
    )
