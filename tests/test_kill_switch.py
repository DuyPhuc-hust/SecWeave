import threading

import pytest

from shared.kill_switch import ExecutionStoppedError, KillSwitch
from shared.models.kill_switch import (
    AuditEventType,
    AutomaticThresholdReason,
    CleanupStatus,
    ExecutionStatus,
    StopSource,
)


def test_new_kill_switch_starts_in_prepared_status(tmp_path):
    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path))
    assert ks.status == ExecutionStatus.PREPARED
    assert ks.is_stopped is False


def test_start_transitions_prepared_to_running(tmp_path):
    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path))
    ks.start()
    assert ks.status == ExecutionStatus.RUNNING


def test_start_twice_raises(tmp_path):
    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path))
    ks.start()
    with pytest.raises(ValueError):
        ks.start()


def test_stop_transitions_running_to_stopped(tmp_path):
    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path))
    ks.start()
    ks.stop(source=StopSource.OPERATOR, reason="manual test stop", actor="operator@secweave.local")
    assert ks.status == ExecutionStatus.STOPPED
    assert ks.is_stopped is True


def test_stop_without_a_cleanup_callable_is_skipped(tmp_path):
    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path), cleanup=None)
    ks.start()
    event = ks.stop(source=StopSource.OPERATOR, reason="no cleanup configured")
    assert event.cleanup_status == CleanupStatus.SKIPPED


def test_stop_runs_the_configured_cleanup_exactly_once(tmp_path):
    calls = []
    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path), cleanup=lambda: calls.append(1))
    ks.start()
    event = ks.stop(source=StopSource.TARGET_OWNER, reason="owner requested stop")
    assert calls == [1]
    assert event.cleanup_status == CleanupStatus.OK


def test_stop_records_who_when_why_in_audit_log(tmp_path):
    ks = KillSwitch(execution_id="exec_audit", storage_dir=str(tmp_path))
    ks.start()
    ks.stop(source=StopSource.INCIDENT_RESPONDER, reason="suspected data leak", actor="ir-oncall")

    entries = ks.read_audit_log()
    assert len(entries) == 2  # start + stop
    entry = entries[-1]
    assert entry["event"] == AuditEventType.STOP.value
    assert entry["source"] == StopSource.INCIDENT_RESPONDER.value
    assert entry["reason"] == "suspected data leak"
    assert entry["actor"] == "ir-oncall"
    assert "at" in entry  # "khi nào"


def test_stop_when_cleanup_raises_still_transitions_to_stopped_and_logs_failure(tmp_path):
    def _broken_cleanup():
        raise RuntimeError("cleanup target unreachable")

    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path), cleanup=_broken_cleanup)
    ks.start()
    event = ks.stop(source=StopSource.INFRA_OWNER, reason="infra incident")

    # A failing cleanup must NOT be allowed to leave the run looking like it's
    # still safe to use — STOPPED must stick regardless of cleanup outcome.
    assert ks.status == ExecutionStatus.STOPPED
    assert event.cleanup_status == CleanupStatus.FAILED
    assert "cleanup target unreachable" in event.cleanup_error


def test_second_stop_call_does_not_rerun_cleanup_but_is_logged(tmp_path):
    calls = []
    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path), cleanup=lambda: calls.append(1))
    ks.start()
    ks.stop(source=StopSource.OPERATOR, reason="first stop")
    second_event = ks.stop(source=StopSource.TARGET_OWNER, reason="second stop, different source")

    assert calls == [1]  # cleanup ran exactly once, not twice
    assert second_event.event == AuditEventType.STOP_REQUESTED_AFTER_ALREADY_STOPPED
    assert len(ks.read_audit_log()) == 3  # start + both stop attempts are on record


def test_resume_raises_from_prepared(tmp_path):
    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path))
    with pytest.raises(ValueError):
        ks.resume()


def test_resume_raises_from_running(tmp_path):
    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path))
    ks.start()
    with pytest.raises(ValueError):
        ks.resume()


def test_resume_transitions_stopped_back_to_running_and_logs(tmp_path):
    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path))
    ks.start()
    ks.stop(source=StopSource.OPERATOR, reason="pausing for review")
    ks.resume(actor="owner@target.example.com", authorization_reference="re-approved via email 2026-08-14")

    assert ks.status == ExecutionStatus.RUNNING
    assert ks.is_stopped is False
    entries = ks.read_audit_log()
    assert entries[-1]["event"] == AuditEventType.RESUME.value
    assert entries[-1]["authorization_reference"] == "re-approved via email 2026-08-14"


def test_audit_log_persists_to_disk_and_is_readable_by_a_new_instance(tmp_path):
    ks1 = KillSwitch(execution_id="exec_persist", storage_dir=str(tmp_path))
    ks1.start()
    ks1.stop(source=StopSource.DATA_ISMS_OWNER, reason="policy violation detected")

    ks2 = KillSwitch(execution_id="exec_persist", storage_dir=str(tmp_path))
    entries = ks2.read_audit_log()
    assert len(entries) == 2  # start + stop
    assert entries[-1]["source"] == StopSource.DATA_ISMS_OWNER.value


def test_new_instance_for_an_already_stopped_execution_recovers_stopped_status(tmp_path):
    # Real bug found via independent review: __init__ used to hardcode
    # PREPARED unconditionally, ignoring any audit log already on disk for
    # this execution_id — so reconstructing a KillSwitch for an execution
    # that was already STOPPED (crash recovery, a separate CLI/API process,
    # a worker restart) silently reset it to PREPARED, and start() would
    # then succeed with zero record of authorization to resume. Status must
    # now be derived from the persisted audit log, not assumed "brand new".
    ks1 = KillSwitch(execution_id="exec_recover_stopped", storage_dir=str(tmp_path))
    ks1.start()
    ks1.stop(source=StopSource.OPERATOR, reason="real stop before recovery test")

    ks2 = KillSwitch(execution_id="exec_recover_stopped", storage_dir=str(tmp_path))
    assert ks2.status == ExecutionStatus.STOPPED
    assert ks2.is_stopped is True
    with pytest.raises(ValueError):
        ks2.start()  # must NOT be able to silently un-stop via start()


def test_new_instance_for_a_running_execution_recovers_running_status(tmp_path):
    ks1 = KillSwitch(execution_id="exec_recover_running", storage_dir=str(tmp_path))
    ks1.start()

    ks2 = KillSwitch(execution_id="exec_recover_running", storage_dir=str(tmp_path))
    assert ks2.status == ExecutionStatus.RUNNING
    assert ks2.is_stopped is False


def test_new_instance_for_a_resumed_execution_recovers_running_status(tmp_path):
    ks1 = KillSwitch(execution_id="exec_recover_resumed", storage_dir=str(tmp_path))
    ks1.start()
    ks1.stop(source=StopSource.OPERATOR, reason="pause")
    ks1.resume(actor="owner", authorization_reference="re-approved")

    ks2 = KillSwitch(execution_id="exec_recover_resumed", storage_dir=str(tmp_path))
    assert ks2.status == ExecutionStatus.RUNNING


def test_new_instance_with_no_prior_history_is_prepared(tmp_path):
    ks = KillSwitch(execution_id="exec_brand_new", storage_dir=str(tmp_path))
    assert ks.status == ExecutionStatus.PREPARED


def test_recovery_uses_sequence_not_physical_write_order_when_a_slow_stop_races_a_resume(tmp_path):
    import time

    # Real bug found via a second independent review pass, introduced BY the
    # earlier fix for the "slow cleanup blocks other callers" problem: once
    # stop()'s audit-log write only happens AFTER its (possibly slow)
    # cleanup finishes, a concurrent resume() on another thread can have its
    # (fast) write land in the file FIRST, even though the resume only
    # became possible because the stop's real transition already happened.
    # Reconstructing a KillSwitch from that log must still recover the true
    # last transition (RUNNING, from the resume), not whichever line
    # physically ended up last being irrelevant, and not whichever line
    # happens to be physically last in the file.
    execution_id = "exec_sequence_race"

    def _slow_cleanup():
        time.sleep(0.3)

    ks = KillSwitch(execution_id=execution_id, storage_dir=str(tmp_path), cleanup=_slow_cleanup)
    ks.start()

    stop_thread = threading.Thread(
        target=ks.stop, kwargs=dict(source=StopSource.OPERATOR, reason="slow stop")
    )
    stop_thread.start()
    time.sleep(0.05)  # let stop() flip status to STOPPED and begin its slow cleanup
    assert ks.is_stopped is True  # the flip already happened before cleanup finished

    # resume() only requires status==STOPPED, which is already true — it can
    # run, finish, and get WRITTEN to disk well before the slow stop's own
    # write happens (that one is still blocked on cleanup's time.sleep).
    ks.resume(actor="owner", authorization_reference="race resume during slow cleanup")
    stop_thread.join(timeout=5)

    assert ks.status == ExecutionStatus.RUNNING  # the live instance has the right answer

    recovered = KillSwitch(execution_id=execution_id, storage_dir=str(tmp_path))
    assert recovered.status == ExecutionStatus.RUNNING  # and so must a freshly reconstructed one


def test_recovery_fails_safe_to_stopped_when_the_audit_log_has_a_corrupted_line(tmp_path):
    # Real gap found via independent review: a corrupted line (e.g. a write
    # torn by a hard crash mid-append — the exact scenario this recovery
    # path exists for) used to make __init__ raise json.JSONDecodeError,
    # meaning the kill switch couldn't even be CONSTRUCTED again after a
    # crash. It must instead assume the safe state (STOPPED) rather than
    # trust a log it can't fully verify.
    execution_id = "exec_corrupt_log"
    ks1 = KillSwitch(execution_id=execution_id, storage_dir=str(tmp_path))
    ks1.start()

    audit_log_path = ks1._audit_log_path
    with open(audit_log_path, "a", encoding="utf-8") as f:
        f.write('{"event": "start", "execution_id": "exec_corrupt_log", "sequence": 2, "at": "unterm\n')

    ks2 = KillSwitch(execution_id=execution_id, storage_dir=str(tmp_path))
    assert ks2.status == ExecutionStatus.STOPPED  # fail safe, not RUNNING/PREPARED
    assert ks2.is_stopped is True
    # read_audit_log() itself must not raise either — it should just skip
    # the unparseable line rather than making the log permanently unreadable.
    assert len(ks2.read_audit_log()) == 1


def test_stop_from_prepared_before_start_is_allowed_and_logged(tmp_path):
    # Deliberate, documented behavior (not an oversight): stop() never
    # requires RUNNING as a precondition, the same way a real emergency-stop
    # button doesn't check whether the machine is on before it's allowed to
    # work. Aborting before start() was ever called must succeed, not raise.
    calls = []
    ks = KillSwitch(
        execution_id="exec_1", storage_dir=str(tmp_path), cleanup=lambda: calls.append(1)
    )
    event = ks.stop(source=StopSource.OPERATOR, reason="abort before start")

    assert ks.status == ExecutionStatus.STOPPED
    assert calls == [1]
    assert event.cleanup_status == CleanupStatus.OK


def test_concurrent_stop_with_slow_cleanup_does_not_block_other_callers_from_being_logged(tmp_path):
    import time

    # Real gap found via independent review: stop() used to hold self._lock
    # across the entire cleanup() call, so a slow/hanging cleanup from the
    # WINNING caller would block every OTHER source's stop() call from
    # returning (or being logged) for as long as that cleanup took — a
    # second source trying to stop things must never be made to wait on the
    # first source's cleanup.
    def _slow_cleanup():
        time.sleep(0.5)

    ks = KillSwitch(execution_id="exec_1", storage_dir=str(tmp_path), cleanup=_slow_cleanup)
    ks.start()

    winner_thread = threading.Thread(
        target=ks.stop, kwargs=dict(source=StopSource.OPERATOR, reason="slow winner")
    )
    winner_thread.start()
    time.sleep(0.1)  # let the winner acquire the lock and start its slow cleanup

    started_at = time.monotonic()
    ks.stop(source=StopSource.INCIDENT_RESPONDER, reason="second caller, must not wait")
    elapsed = time.monotonic() - started_at

    winner_thread.join(timeout=5)
    assert elapsed < 0.3  # must return almost immediately, NOT after the 0.5s cleanup
    assert len(ks.read_audit_log()) == 3  # start + winner's stop + loser's duplicate-stop


@pytest.mark.parametrize(
    "source,reason,actor",
    [
        (StopSource.OPERATOR, "operator drill", "operator@secweave.local"),
        (StopSource.TARGET_OWNER, "owner drill (simulated)", "owner@target.example.com"),
        (
            StopSource.AUTOMATIC_THRESHOLD,
            AutomaticThresholdReason.COST_CAP_EXCEEDED.value,
            None,
        ),
    ],
)
def test_kill_switch_drill_from_each_required_source(tmp_path, source, reason, actor):
    # Weekly plan Tuần 6's "Kill-switch drill (bắt buộc, có checklist ký)":
    # trigger a stop from operator, owner (simulated), and the automatic
    # cost-cap threshold, each tried once -> assert 100% transition to
    # STOPPED, cleanup runs per the approved plan, audit log has who/when/why.
    cleanup_ran = []
    ks = KillSwitch(
        execution_id=f"exec_drill_{source.value}",
        storage_dir=str(tmp_path),
        cleanup=lambda: cleanup_ran.append(True),
    )
    ks.start()
    ks.stop(source=source, reason=reason, actor=actor)

    assert ks.status == ExecutionStatus.STOPPED
    assert cleanup_ran == [True]
    entries = ks.read_audit_log()
    stop_entry = entries[-1]  # entries[0] is the start() event, no source/reason on it
    assert stop_entry["source"] == source.value
    assert stop_entry["reason"] == reason
    assert "at" in stop_entry


def test_concurrent_stop_calls_run_cleanup_exactly_once_and_never_crash(tmp_path):
    # Real scenario this guards against: 2 sources (e.g. operator and the
    # automatic cost-cap threshold) noticing a problem and calling stop() at
    # nearly the same instant. Without the lock in KillSwitch.stop(), both
    # could observe status==RUNNING before either writes STOPPED, and both
    # would then run cleanup — violating "cleanup đã duyệt tại Gate 3" being
    # a single, predictable action. Uses a real thread barrier to force
    # genuine concurrent access, same technique already proven necessary for
    # EvidenceHarness.generate_marker()'s own race fix.
    cleanup_calls = []
    cleanup_lock = threading.Lock()

    def _cleanup():
        with cleanup_lock:
            cleanup_calls.append(1)

    ks = KillSwitch(execution_id="exec_race", storage_dir=str(tmp_path), cleanup=_cleanup)
    ks.start()

    barrier = threading.Barrier(8)
    errors = []

    def _call(i):
        try:
            barrier.wait(timeout=5)
            ks.stop(source=StopSource.OPERATOR, reason=f"racer {i}", actor=f"racer-{i}")
        except Exception as exc:  # noqa: BLE001 - test needs to see ANY failure
            errors.append(exc)

    threads = [threading.Thread(target=_call, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert errors == []
    assert cleanup_calls == [1]
    assert ks.status == ExecutionStatus.STOPPED
    assert len(ks.read_audit_log()) == 9  # start + 8 stop attempts, only 1 actually cleaned up


def test_evidence_harness_capture_raises_execution_stopped_error_when_stopped(tmp_path):
    # Cross-module integration: EvidenceHarness must actually refuse to send
    # a real request once the shared KillSwitch is STOPPED — a KillSwitch
    # that exists but nothing checks would be pure decoration.
    import httpx

    from evidence_harness.harness import EvidenceHarness
    from shared.models.action import ActionSpec, ActionType
    from shared.models.observation import ObservationRole

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    ks = KillSwitch(execution_id="exec_integration", storage_dir=str(tmp_path / "kill_switch"))
    ks.start()
    ks.stop(source=StopSource.OPERATOR, reason="stop before any capture")

    harness = EvidenceHarness(
        execution_id="exec_integration",
        target_id="tgt_1",
        target_revision_id="rev_1",
        storage_dir=str(tmp_path / "evidence"),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        kill_switch=ks,
    )
    action = ActionSpec(
        type=ActionType.READ_ONLY,
        method="GET",
        target="https://target.example.com/api/objects/1",
        description="Should never actually be sent.",
    )

    with pytest.raises(ExecutionStoppedError):
        harness.capture(action, role=ObservationRole.MAIN)

    assert calls == []  # the real transport was never touched
