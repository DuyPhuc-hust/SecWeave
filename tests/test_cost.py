import threading

import pytest
from pydantic import ValidationError

from shared.cost import CostService, check_planned_action_cap
from shared.models.action import ActionPlan, ActionSpec, ActionType


def _plan_with_n_actions(n: int) -> ActionPlan:
    action = ActionSpec(
        type=ActionType.READ_ONLY,
        method="GET",
        target="https://staging.example.com/api/objects/1",
        description="Read object 1.",
    )
    return ActionPlan(hypothesis_id="hyp_test1", actions=[action for _ in range(n)])


def test_plan_within_cap_is_allowed():
    decision = check_planned_action_cap(_plan_with_n_actions(3), cap=5)
    assert decision.allowed is True
    assert decision.planned_action_count == 3
    assert decision.cap == 5


def test_plan_exactly_at_cap_is_allowed():
    decision = check_planned_action_cap(_plan_with_n_actions(5), cap=5)
    assert decision.allowed is True


def test_plan_exceeding_cap_is_denied():
    decision = check_planned_action_cap(_plan_with_n_actions(6), cap=5)
    assert decision.allowed is False
    assert "vượt cap" in decision.reason
    assert decision.planned_action_count == 6
    assert decision.cap == 5


def test_empty_plan_cannot_be_constructed():
    # Real gap found via independent review: an empty ActionPlan used to be
    # constructible, making check_plan()'s all(...) over zero checks
    # vacuously True ("approved") and check_planned_action_cap's count=0
    # trivially within any cap — "approved, 0 actions" is never a
    # meaningful state to report as safe. ActionPlan.actions now requires
    # min_length=1, so this can't even be constructed in the first place —
    # same "an ambiguous/empty state must never look identical to a
    # verified-safe one" principle already applied to PlanCheckResult/
    # CostDecision's own consistency validators.
    with pytest.raises(ValidationError):
        _plan_with_n_actions(0)


# ----- CostService: the RUNTIME gate (weekly plan Tuần 6), distinct from
# check_planned_action_cap's planning-time-only check above. -----


def test_cost_service_allows_actions_within_cap(tmp_path):
    service = CostService(execution_id="exec_1", storage_dir=str(tmp_path), cap=3)
    for i in range(3):
        decision = service.record_action(f"act_{i}")
        assert decision.allowed is True
        assert decision.executed_action_count == i  # count BEFORE this action
    assert service.executed_action_count == 3


def test_cost_service_refuses_the_action_that_would_exceed_cap(tmp_path):
    service = CostService(execution_id="exec_1", storage_dir=str(tmp_path), cap=2)
    service.record_action("act_1")
    service.record_action("act_2")
    decision = service.record_action("act_3")
    assert decision.allowed is False
    assert decision.executed_action_count == 2
    assert decision.cap == 2
    assert "act_3" in decision.reason


def test_cost_service_does_not_increment_count_on_repeated_refusal(tmp_path):
    # A refused action never actually executed, so it must not silently
    # inflate the running count — repeatedly hitting a maxed-out cap must
    # stay stable, not drift upward from refusals alone.
    service = CostService(execution_id="exec_1", storage_dir=str(tmp_path), cap=1)
    service.record_action("act_1")
    for _ in range(5):
        decision = service.record_action("act_refused")
        assert decision.allowed is False
        assert decision.executed_action_count == 1
    assert service.executed_action_count == 1


def test_cost_service_cap_zero_refuses_the_first_action(tmp_path):
    service = CostService(execution_id="exec_1", storage_dir=str(tmp_path), cap=0)
    decision = service.record_action("act_1")
    assert decision.allowed is False
    assert decision.executed_action_count == 0


def test_cost_service_recovers_count_from_existing_audit_log_after_restart(tmp_path):
    # Real safety property this must have (mirrors KillSwitch's own crash-
    # recovery reasoning): a process restart mid-run must NOT reset the
    # count to 0, or a capped run could silently exceed its true total
    # across the restart.
    service1 = CostService(execution_id="exec_restart", storage_dir=str(tmp_path), cap=5)
    service1.record_action("act_1")
    service1.record_action("act_2")
    service1.record_action("act_3")

    service2 = CostService(execution_id="exec_restart", storage_dir=str(tmp_path), cap=5)
    assert service2.executed_action_count == 3
    decision = service2.record_action("act_4")
    assert decision.allowed is True
    assert decision.executed_action_count == 3  # continues from where service1 left off


def test_cost_service_refuses_to_reopen_an_execution_id_with_a_different_cap(tmp_path):
    # Real gap found via independent review: `cap` was never itself
    # persisted/cross-checked — only the executed-action count was
    # recovered across a restart. An operator (or a wrapper script bug)
    # reusing the same execution_id with a HIGHER --cap on a later
    # invocation used to silently widen the true budget past what was
    # originally reviewed/approved for this execution.
    service1 = CostService(execution_id="exec_cap_durability", storage_dir=str(tmp_path), cap=1)
    service1.record_action("act_1")

    with pytest.raises(RuntimeError):
        CostService(execution_id="exec_cap_durability", storage_dir=str(tmp_path), cap=100)

    # Reopening with the SAME cap must still work exactly as before.
    service2 = CostService(execution_id="exec_cap_durability", storage_dir=str(tmp_path), cap=1)
    assert service2.executed_action_count == 1


def test_cost_service_tolerates_a_corrupted_trailing_line_by_counting_it_conservatively(tmp_path):
    # Same "fail safe = assume the worst" reasoning as KillSwitch's own
    # corrupted-line recovery (shared/kill_switch.py), applied to a counter
    # instead of a status: a crash mid-write can only tear the LAST line, and
    # that torn line represents an action that WAS being attempted — an
    # undercount here would let a restart quietly exceed the true cap.
    service1 = CostService(execution_id="exec_corrupt", storage_dir=str(tmp_path), cap=10)
    service1.record_action("act_1")
    service1.record_action("act_2")

    audit_log_path = service1._audit_log_path
    with open(audit_log_path, "a", encoding="utf-8") as f:
        f.write('{"action_ref": "act_3", "sequence": 3, "at": "unterminated\n')

    service2 = CostService(execution_id="exec_corrupt", storage_dir=str(tmp_path), cap=10)
    assert service2.executed_action_count == 3  # 2 valid lines + 1 corrupted line counted


def test_cost_service_does_not_merge_a_new_entry_onto_a_torn_trailing_line(tmp_path):
    # Real bug found via independent review: a torn last line (no trailing
    # newline, from a crash mid-write) used to get the NEXT legitimate entry
    # concatenated directly onto its tail with no separator — merging one
    # real, would-be-recoverable entry into a single line that then NEVER
    # parses, permanently losing it from the count (recovery only ever
    # credits a corrupted line +1, never +2, no matter how many real entries
    # got merged into it) — this could grow across further restarts,
    # letting a capped run silently exceed its true total.
    service1 = CostService(execution_id="exec_torn", storage_dir=str(tmp_path), cap=10)
    service1.record_action("act_1")

    audit_log_path = service1._audit_log_path
    with open(audit_log_path, "a", encoding="utf-8") as f:
        f.write('{"action_ref": "act_2", "sequence": 2, "at": "unterminated')  # no trailing \n

    service2 = CostService(execution_id="exec_torn", storage_dir=str(tmp_path), cap=10)
    assert service2.executed_action_count == 2  # act_1 (valid) + torn act_2 (counted conservatively)
    service2.record_action("act_3")

    # The key assertion: act_3 must land on its OWN line, not merged onto
    # the torn act_2 line — so a THIRD restart still recovers correctly.
    service3 = CostService(execution_id="exec_torn", storage_dir=str(tmp_path), cap=10)
    assert service3.executed_action_count == 3  # act_1 + torn-act_2 + act_3, nothing lost


def test_cost_service_record_action_does_not_advance_count_when_the_durable_write_fails(
    tmp_path, monkeypatch
):
    # Real bug found via independent review: self._count used to be
    # incremented BEFORE the durable write — if the write then failed (disk
    # full, permission lost, etc.), the in-memory count stayed permanently
    # ahead of what was actually persisted for the rest of this process's
    # life, silently diverging from what a fresh restart would correctly
    # recover (the lower, actually-durable value).
    service = CostService(execution_id="exec_io_fail", storage_dir=str(tmp_path), cap=10)
    audit_log_path = str(service._audit_log_path)
    real_open = open

    def _broken_open(path, mode="r", *args, **kwargs):
        if "a" in mode and str(path) == audit_log_path:
            raise OSError("simulated disk failure")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _broken_open)

    with pytest.raises(RuntimeError):
        service.record_action("act_1")

    assert service.executed_action_count == 0  # NOT advanced despite the failed write


def test_cost_service_stays_correct_under_many_concurrent_calls(tmp_path):
    # Real scenario this guards against: multiple threads (e.g. parallel
    # action execution) hitting record_action() near the cap boundary at
    # nearly the same instant — without correct locking, two callers could
    # both read the same pre-increment count and both be told "allowed",
    # letting the cap be exceeded by more than the intended single action.
    service = CostService(execution_id="exec_race", storage_dir=str(tmp_path), cap=5)
    allowed_count = []
    allowed_lock = threading.Lock()
    barrier = threading.Barrier(20)

    def _call(i):
        barrier.wait(timeout=5)  # force genuinely concurrent access, not just sequential starts
        decision = service.record_action(f"act_{i}")
        if decision.allowed:
            with allowed_lock:
                allowed_count.append(i)

    threads = [threading.Thread(target=_call, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert len(allowed_count) == 5  # exactly cap, never more
    assert service.executed_action_count == 5


def test_cost_service_record_action_holds_the_lock_during_the_critical_section(tmp_path):
    # A GIL-only race on record_action()'s bare read-then-increment (with no
    # syscall in between) turns out to be practically unhittable via plain
    # thread contention alone — empirically confirmed via 20 trials of 200
    # concurrent threads racing an unlocked version of this method, which
    # NEVER once exceeded the cap. That means the test above, on its own,
    # would silently keep passing even if the lock were removed entirely —
    # exactly the "decorative test" failure mode this project's mutation-
    # testing discipline exists to catch. This test instead directly proves
    # record_action() actually acquires `self._lock` for its critical
    # section: holding the lock from the TEST itself must block a
    # concurrent record_action() call until released, regardless of GIL
    # timing luck.
    service = CostService(execution_id="exec_lock_probe", storage_dir=str(tmp_path), cap=5)
    service._lock.acquire()
    result: dict = {}

    def _call():
        result["decision"] = service.record_action("act_1")

    t = threading.Thread(target=_call)
    t.start()
    t.join(timeout=0.2)
    assert t.is_alive()  # still blocked, waiting for the externally-held lock
    assert "decision" not in result

    service._lock.release()
    t.join(timeout=5)
    assert result["decision"].allowed is True


def test_runtime_cost_decision_rejects_allowed_true_when_count_at_cap():
    from shared.models.action import RuntimeCostDecision

    with pytest.raises(ValidationError):
        RuntimeCostDecision(allowed=True, reason="ok", executed_action_count=5, cap=5)


def test_runtime_cost_decision_rejects_allowed_false_when_count_under_cap():
    from shared.models.action import RuntimeCostDecision

    with pytest.raises(ValidationError):
        RuntimeCostDecision(allowed=False, reason="ok", executed_action_count=2, cap=5)


def test_runtime_cost_decision_accepts_consistent_construction():
    from shared.models.action import RuntimeCostDecision

    allowed = RuntimeCostDecision(allowed=True, reason="ok", executed_action_count=4, cap=5)
    assert allowed.allowed is True
    refused = RuntimeCostDecision(allowed=False, reason="over cap", executed_action_count=5, cap=5)
    assert refused.allowed is False


def test_two_separate_cost_service_instances_racing_record_action_never_jointly_exceed_cap(tmp_path):
    # The actual cross-process race this closes: 2 SEPARATE CostService
    # instances (simulating 2 separate processes sharing one execution_id/
    # storage_dir) each have their OWN threading.Lock — that lock alone
    # gives zero mutual exclusion between them. Only the shared file lock
    # (each instance's own file descriptor, contending over the SAME
    # on-disk .lock file) can prevent both from reading the same stale
    # count and both recording an action past cap. Uses real, separately-
    # constructed instances (not one instance shared across threads,
    # which self._lock alone would already serialize) to force genuine
    # cross-instance contention.
    execution_id = "exec_cross_instance_cost_race"
    cap = 5
    n_workers = 20
    instances = [CostService(execution_id=execution_id, storage_dir=str(tmp_path), cap=cap) for _ in range(n_workers)]
    barrier = threading.Barrier(n_workers)
    results = []
    results_lock = threading.Lock()
    errors = []

    def _call(i):
        try:
            barrier.wait(timeout=5)
            decision = instances[i].record_action(f"action_{i}")
            with results_lock:
                results.append(decision.allowed)
        except Exception as exc:  # noqa: BLE001 - test needs to see ANY failure
            errors.append(exc)

    threads = [threading.Thread(target=_call, args=(i,)) for i in range(n_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert errors == []
    assert sum(1 for allowed in results if allowed) == cap  # exactly cap successes, never more
    assert sum(1 for allowed in results if not allowed) == n_workers - cap

    # A freshly-constructed instance must recover the SAME, non-exceeded count.
    final = CostService(execution_id=execution_id, storage_dir=str(tmp_path), cap=cap)
    assert final.executed_action_count == cap
