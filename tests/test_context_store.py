import json
import sqlite3

import pytest

from context_store.store import SecurityContextStore
from shared.models.hypothesis import (
    Hypothesis,
    HypothesisProvenance,
    HypothesisResult,
    HypothesisStatus,
)
from shared.models.signal import SignalCoverage
from tests.factories import semgrep_sqli_signal

_signal = semgrep_sqli_signal


def test_get_verified_context_empty_by_default():
    store = SecurityContextStore(db_path=":memory:")
    assert store.get_verified_context("target_1") == []
    store.close()


def test_get_verified_context_filters_by_target_id():
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "Object ownership checked on GET /objects/:id")
    store.promote_execution_to_verified("exec_1", "pkg_1")
    store.record_unverified_observation("target_2", "exec_2", "Unrelated target observation")
    store.promote_execution_to_verified("exec_2", "pkg_2")

    result = store.get_verified_context("target_1")
    assert len(result) == 1
    assert result[0]["description"] == "Object ownership checked on GET /objects/:id"
    store.close()


def test_record_unverified_observation_not_returned_by_get_verified_context():
    # SPEC §4.6 diagram: "giả thuyết lượt sau CHỈ dựa trên verified" —
    # an observation Evidence Harness just captured, with no Human Review
    # yet, must never feed the Hypothesis Engine's trusted context.
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "Not yet reviewed by anyone")

    assert store.get_verified_context("target_1") == []
    store.close()


def test_get_unverified_context_returns_it_with_a_warning_label():
    # SPEC §4.6 diagram's dashed arrow: "unverified: chỉ tra cứu, có
    # nhãn cảnh báo" — this pathway exists, but every result must carry an
    # explicit warning so nothing downstream mistakes it for confirmed fact.
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "Not yet reviewed by anyone")

    result = store.get_unverified_context("target_1")
    assert len(result) == 1
    assert result[0]["description"] == "Not yet reviewed by anyone"
    assert "CHƯA XÁC MINH" in result[0]["warning"]
    store.close()


def test_promote_execution_to_verified_moves_it_out_of_unverified_context():
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "obs")
    assert len(store.get_unverified_context("target_1")) == 1

    promoted = store.promote_execution_to_verified("exec_1", "pkg_1")

    assert promoted == 1
    assert store.get_unverified_context("target_1") == []
    assert len(store.get_verified_context("target_1")) == 1
    store.close()


def test_promote_execution_to_verified_only_touches_the_named_execution():
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "obs A")
    store.record_unverified_observation("target_1", "exec_2", "obs B")

    promoted = store.promote_execution_to_verified("exec_1", "pkg_1")

    assert promoted == 1
    assert len(store.get_verified_context("target_1")) == 1
    assert len(store.get_unverified_context("target_1")) == 1


def test_promote_execution_to_verified_is_not_re_stamped_on_a_second_call():
    # A real reviewer decision should extend trust ONCE, not silently
    # refresh the expiry every time review-package happens to run again
    # against the same execution.
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "obs")
    first = store.promote_execution_to_verified("exec_1", "pkg_1")
    second = store.promote_execution_to_verified("exec_1", "pkg_2")

    assert first == 1
    assert second == 0  # nothing left in unverified status to promote
    store.close()


def test_get_verified_context_excludes_an_expired_entry():
    # SPEC §4.6: "Kết luận 'an toàn' không có thời hạn" must never be
    # stored — verify the expiry is actually enforced, not just recorded.
    # Backdates valid_until directly (bypassing promote_execution_to_
    # verified's own valid_for_days bound check, which is a SEPARATE
    # concern this test isn't exercising) to test the READ-side exclusion
    # in isolation.
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "obs")
    store.promote_execution_to_verified("exec_1", "pkg_1", valid_for_days=1)
    store._conn.execute(
        "UPDATE verified_observations SET valid_until = '2000-01-01T00:00:00+00:00' WHERE target_id = ?",
        ("target_1",),
    )
    store._conn.commit()

    assert store.get_verified_context("target_1") == []
    store.close()


def test_promote_execution_to_verified_rejects_non_positive_valid_for_days():
    # Real gap found via independent review: no bound check meant a
    # non-positive valid_for_days silently promoted a row to
    # status='verified' with valid_until already in the past — since
    # promotion only ever matches status='unverified', that row could
    # never be promoted again with a correct expiry, permanently lost from
    # get_verified_context().
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "obs")

    with pytest.raises(ValueError):
        store.promote_execution_to_verified("exec_1", "pkg_1", valid_for_days=0)
    with pytest.raises(ValueError):
        store.promote_execution_to_verified("exec_1", "pkg_1", valid_for_days=-5)

    # The row must still be cleanly promotable afterward — a rejected call
    # must not have left it half-modified.
    assert store.promote_execution_to_verified("exec_1", "pkg_1") == 1
    store.close()


def test_promote_execution_to_verified_rejects_an_absurdly_large_valid_for_days():
    # Real gap found via independent review: an extreme value (near
    # datetime's max representable range) raised an uncaught OverflowError
    # instead of a clean, catchable error.
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "obs")

    with pytest.raises(ValueError):
        store.promote_execution_to_verified("exec_1", "pkg_1", valid_for_days=999_999_999)
    store.close()


def test_mark_stale_removes_both_verified_and_unverified_rows_from_both_read_paths():
    # SPEC §4.6's staleness principle: mark a BROADER scope stale rather
    # than risk keeping a fact that might now be wrong — applies to BOTH
    # unverified and verified rows for the target, not just one.
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "still unverified")
    store.record_unverified_observation("target_1", "exec_2", "will be verified")
    store.promote_execution_to_verified("exec_2", "pkg_1")

    marked = store.mark_stale("target_1", "target_1's revision changed, scope of impact unclear")

    assert marked == 2
    assert store.get_verified_context("target_1") == []
    assert store.get_unverified_context("target_1") == []
    store.close()


def test_mark_stale_does_not_affect_other_targets():
    store = SecurityContextStore(db_path=":memory:")
    store.record_unverified_observation("target_1", "exec_1", "obs")
    store.promote_execution_to_verified("exec_1", "pkg_1")
    store.record_unverified_observation("target_2", "exec_2", "obs")
    store.promote_execution_to_verified("exec_2", "pkg_2")

    store.mark_stale("target_1", "revision changed")

    assert store.get_verified_context("target_1") == []
    assert len(store.get_verified_context("target_2")) == 1
    store.close()


def test_get_unverified_context_raises_runtime_error_not_a_raw_sqlite_error():
    store = SecurityContextStore(db_path=":memory:")
    store.close()
    with pytest.raises(RuntimeError):
        store.get_unverified_context("target_1")


def test_promote_execution_to_verified_raises_runtime_error_not_a_raw_sqlite_error():
    store = SecurityContextStore(db_path=":memory:")
    store.close()
    with pytest.raises(RuntimeError):
        store.promote_execution_to_verified("exec_1", "pkg_1")


def test_mark_stale_raises_runtime_error_not_a_raw_sqlite_error():
    store = SecurityContextStore(db_path=":memory:")
    store.close()
    with pytest.raises(RuntimeError):
        store.mark_stale("target_1", "reason")


def test_record_unverified_observation_raises_runtime_error_not_a_raw_sqlite_error():
    store = SecurityContextStore(db_path=":memory:")
    store.close()
    with pytest.raises(RuntimeError):
        store.record_unverified_observation("target_1", "exec_1", "obs")


def test_opens_pre_existing_db_missing_verified_observations_columns_without_crashing(tmp_path):
    # Simulates a .secweave/context.db created before this migration —
    # reopening it must not break, and every OLD row (written when
    # get_verified_context() had no unverified/expiry concept at all) must
    # be treated as already-verified (meaning-preserving backfill), not
    # silently dropped or crash the read path — but also must NOT be
    # treated as trusted forever (NULL valid_until on a migrated row is
    # excluded, per SPEC's ban on unbounded safe conclusions).
    db_path = str(tmp_path / "old_schema.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE verified_observations (
            id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL,
            description TEXT NOT NULL,
            verified_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO verified_observations (id, target_id, description, verified_at) VALUES (?, ?, ?, ?)",
        ("obs_old", "target_1", "written before this migration existed", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()

    store = SecurityContextStore(db_path=db_path)
    # Old row is not returned as verified context — NULL valid_until means
    # "unknown expiry," excluded rather than trusted forever.
    assert store.get_verified_context("target_1") == []
    # But the migration itself must not crash, and a fresh write/promote
    # cycle must work normally afterward.
    store.record_unverified_observation("target_1", "exec_new", "written after migration")
    store.promote_execution_to_verified("exec_new", "pkg_new")
    assert len(store.get_verified_context("target_1")) == 1
    store.close()


def test_record_and_get_hypothesis_roundtrip():
    store = SecurityContextStore(db_path=":memory:")
    signal = _signal()
    hypothesis = Hypothesis(
        hypothesis_id="hyp_abc123",
        expected_behavior="a",
        suspected_behavior="b",
        observation_criteria="c",
        provenance=HypothesisProvenance(
            source_tool="semgrep",
            source_signal_id=signal.signal_id,
            coverage=SignalCoverage.COMPLETE,
            location=signal.location,
        ),
    )
    result = HypothesisResult(status=HypothesisStatus.HYPOTHESIS, hypothesis=hypothesis)

    store.record_hypothesis(result, signal)
    record = store.get_hypothesis("hyp_abc123")

    assert record is not None
    assert record["hypothesis_id"] == "hyp_abc123"
    assert record["signal_id"] == "sig_test1"
    assert record["source_tool"] == "semgrep"
    assert record["status"] == "hypothesis"
    assert record["expected_behavior"] == "a"
    assert record["reason"] is None
    assert json.loads(record["location"]) == json.loads(signal.location.model_dump_json())
    store.close()


def test_record_not_verifiable_result_retrievable_by_signal_id():
    store = SecurityContextStore(db_path=":memory:")
    signal = _signal()
    result = HypothesisResult(
        status=HypothesisStatus.NOT_VERIFIABLE,
        reason="Signal quá mơ hồ, không tách được hành vi đúng/sai.",
    )

    store.record_hypothesis(result, signal)

    # No hypothesis_id (since no Hypothesis was ever created), so
    # get_hypothesis() can't look it up — but it must be queryable via
    # signal_id, per SPEC §4.6's requirement that "a hypothesis that was
    # rejected along with its reason" must be both stored AND retrievable,
    # not just sit unread in the DB.
    records = store.get_hypotheses_by_signal_id(signal.signal_id)
    assert len(records) == 1
    assert records[0]["hypothesis_id"] is None
    assert records[0]["status"] == "not_verifiable"
    assert records[0]["reason"] == "Signal quá mơ hồ, không tách được hành vi đúng/sai."
    store.close()


def test_get_hypotheses_by_signal_id_returns_all_attempts_in_order():
    store = SecurityContextStore(db_path=":memory:")
    signal = _signal()
    store.record_hypothesis(
        HypothesisResult(status=HypothesisStatus.NOT_VERIFIABLE, reason="lần 1: chưa đủ ngữ cảnh"),
        signal,
    )
    hypothesis = Hypothesis(
        hypothesis_id="hyp_retry",
        expected_behavior="a",
        suspected_behavior="b",
        observation_criteria="c",
        provenance=HypothesisProvenance(
            source_tool="semgrep",
            source_signal_id=signal.signal_id,
            coverage=SignalCoverage.COMPLETE,
            location=signal.location,
        ),
    )
    store.record_hypothesis(
        HypothesisResult(status=HypothesisStatus.HYPOTHESIS, hypothesis=hypothesis), signal
    )

    records = store.get_hypotheses_by_signal_id(signal.signal_id)
    assert len(records) == 2
    assert records[0]["status"] == "not_verifiable"
    assert records[1]["status"] == "hypothesis"
    assert records[1]["hypothesis_id"] == "hyp_retry"
    store.close()


def test_get_hypothesis_returns_none_when_not_found():
    store = SecurityContextStore(db_path=":memory:")
    assert store.get_hypothesis("hyp_does_not_exist") is None
    store.close()


def test_record_hypothesis_raises_clean_runtime_error_on_db_error():
    store = SecurityContextStore(db_path=":memory:")
    signal = _signal()
    result = HypothesisResult(status=HypothesisStatus.NOT_VERIFIABLE, reason="x")

    class _FailingConnection:
        def execute(self, *args, **kwargs):
            raise sqlite3.OperationalError("simulated disk I/O error")

    store._conn = _FailingConnection()

    with pytest.raises(RuntimeError, match="Không ghi được hypothesis"):
        store.record_hypothesis(result, signal)


def test_opens_pre_existing_db_missing_location_column_without_crashing(tmp_path):
    # Simulates a .secweave/context.db created by an older version of the
    # code (before the location column was added) — reopening it with the
    # new code must not break with "no such column".
    db_path = str(tmp_path / "old_schema.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE hypotheses (
            row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            hypothesis_id TEXT UNIQUE,
            signal_id TEXT NOT NULL,
            source_tool TEXT NOT NULL,
            status TEXT NOT NULL,
            expected_behavior TEXT,
            suspected_behavior TEXT,
            observation_criteria TEXT,
            reason TEXT,
            coverage TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

    store = SecurityContextStore(db_path=db_path)
    signal = _signal()
    hypothesis = Hypothesis(
        hypothesis_id="hyp_after_migration",
        expected_behavior="a",
        suspected_behavior="b",
        observation_criteria="c",
        provenance=HypothesisProvenance(
            source_tool="semgrep",
            source_signal_id=signal.signal_id,
            coverage=SignalCoverage.COMPLETE,
            location=signal.location,
        ),
    )
    store.record_hypothesis(HypothesisResult(status=HypothesisStatus.HYPOTHESIS, hypothesis=hypothesis), signal)
    record = store.get_hypothesis("hyp_after_migration")
    store.close()

    assert record is not None
    assert json.loads(record["location"]) == json.loads(signal.location.model_dump_json())


def test_default_db_path_persists_to_disk(tmp_path, monkeypatch):
    db_file = tmp_path / "nested" / "context.db"
    monkeypatch.chdir(tmp_path)
    store = SecurityContextStore(db_path="nested/context.db")
    store.close()
    assert db_file.exists()


def test_constructor_raises_sqlite_error_when_parent_path_is_a_file_not_a_directory(tmp_path):
    # Real gap found via independent review: Path(db_path).parent.mkdir(...)
    # used to raise a plain OSError here, which every cli.py call site
    # catching only sqlite3.Error (the documented, natural failure mode for
    # "the store couldn't be opened") never caught — dumped a raw traceback
    # instead of a clean error.
    blocking_file = tmp_path / "not_a_dir"
    blocking_file.write_text("i am a file, not a directory")
    db_path = str(blocking_file / "context.db")

    with pytest.raises(sqlite3.Error):
        SecurityContextStore(db_path=db_path)


def test_get_hypothesis_raises_runtime_error_not_a_raw_sqlite_error():
    # Real gap found via independent review: unlike record_hypothesis(),
    # the 3 read methods had zero exception handling — a real sqlite
    # failure used to escape as a raw sqlite3.Error instead of the
    # RuntimeError every other Context Store failure raises.
    store = SecurityContextStore(db_path=":memory:")
    store.close()  # any query after this raises a real sqlite3.Error
    with pytest.raises(RuntimeError):
        store.get_hypothesis("hyp_1")


def test_get_verified_context_raises_runtime_error_not_a_raw_sqlite_error():
    store = SecurityContextStore(db_path=":memory:")
    store.close()
    with pytest.raises(RuntimeError):
        store.get_verified_context("target_1")


def test_get_hypotheses_by_signal_id_raises_runtime_error_not_a_raw_sqlite_error():
    store = SecurityContextStore(db_path=":memory:")
    store.close()
    with pytest.raises(RuntimeError):
        store.get_hypotheses_by_signal_id("sig_1")
