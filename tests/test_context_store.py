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
    store._conn.execute(
        "INSERT INTO verified_observations (id, target_id, description, verified_at) "
        "VALUES (?, ?, ?, ?)",
        ("obs_1", "target_1", "Object ownership checked on GET /objects/:id", "2026-08-01T00:00:00Z"),
    )
    store._conn.execute(
        "INSERT INTO verified_observations (id, target_id, description, verified_at) "
        "VALUES (?, ?, ?, ?)",
        ("obs_2", "target_2", "Unrelated target observation", "2026-08-01T00:00:00Z"),
    )
    store._conn.commit()

    result = store.get_verified_context("target_1")
    assert len(result) == 1
    assert result[0]["id"] == "obs_1"
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
            source_tool="semgrep", source_signal_id=signal.signal_id, coverage=SignalCoverage.COMPLETE
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
    store.close()


def test_record_not_verifiable_result_retrievable_by_signal_id():
    store = SecurityContextStore(db_path=":memory:")
    signal = _signal()
    result = HypothesisResult(
        status=HypothesisStatus.NOT_VERIFIABLE,
        reason="Signal quá mơ hồ, không tách được hành vi đúng/sai.",
    )

    store.record_hypothesis(result, signal)

    # Không có hypothesis_id (vì không có Hypothesis nào được tạo) nên
    # get_hypothesis() không tra được — nhưng phải tra được qua signal_id, đúng
    # yêu cầu SPEC §4.6 "giả thuyết đã bị bác bỏ kèm lý do" phải lưu lại VÀ
    # lấy lại được, không chỉ nằm im trong DB không ai đọc tới.
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
            source_tool="semgrep", source_signal_id=signal.signal_id, coverage=SignalCoverage.COMPLETE
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


def test_default_db_path_persists_to_disk(tmp_path, monkeypatch):
    db_file = tmp_path / "nested" / "context.db"
    monkeypatch.chdir(tmp_path)
    store = SecurityContextStore(db_path="nested/context.db")
    store.close()
    assert db_file.exists()
