from context_store.store import SecurityContextStore
from shared.models.hypothesis import (
    Hypothesis,
    HypothesisProvenance,
    HypothesisResult,
    HypothesisStatus,
)
from shared.models.signal import (
    NormalizedSignal,
    RawReference,
    RuleInfo,
    SastLocation,
    SeverityInfo,
    SignalCoverage,
    SignalSource,
    SignalType,
    TargetHint,
)


def _signal():
    return NormalizedSignal(
        signal_id="sig_test1",
        source=SignalSource(
            tool="semgrep", tool_version="1.78.0", type=SignalType.SAST, coverage=SignalCoverage.COMPLETE
        ),
        rule=RuleInfo(id="python.django.security.audit.sqli", name="Potential SQL injection", cwe=["CWE-89"]),
        severity=SeverityInfo(raw="ERROR", normalized="high"),
        location=SastLocation(file_path="app/views.py", start_line=42, end_line=42),
        signal_context="cursor.execute(query % user_id)",
        target_hint=TargetHint(),
        ingested_at="2026-08-12T00:00:00Z",
        raw_reference=RawReference(storage_path="x", hash="sha256:0"),
    )


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


def test_record_not_verifiable_result_without_hypothesis_id():
    store = SecurityContextStore(db_path=":memory:")
    signal = _signal()
    result = HypothesisResult(
        status=HypothesisStatus.NOT_VERIFIABLE,
        reason="Signal quá mơ hồ, không tách được hành vi đúng/sai.",
    )

    store.record_hypothesis(result, signal)

    # Không có hypothesis_id (vì không có Hypothesis nào được tạo) nên không tra
    # cứu được qua get_hypothesis — nhưng bản ghi vẫn tồn tại trong bảng, đúng
    # yêu cầu SPEC §4.6 "giả thuyết đã bị bác bỏ kèm lý do" phải được lưu lại.
    cursor = store._conn.execute(
        "SELECT signal_id, status, reason FROM hypotheses WHERE signal_id = ?",
        (signal.signal_id,),
    )
    row = cursor.fetchone()
    assert row == ("sig_test1", "not_verifiable", "Signal quá mơ hồ, không tách được hành vi đúng/sai.")
    store.close()


def test_get_hypothesis_returns_none_when_not_found():
    store = SecurityContextStore(db_path=":memory:")
    assert store.get_hypothesis("hyp_does_not_exist") is None
    store.close()


def test_default_db_path_persists_to_disk(tmp_path, monkeypatch):
    db_file = tmp_path / "nested" / "context.db"
    monkeypatch.chdir(tmp_path)
    store = SecurityContextStore(db_path="nested/context.db")
    store.close()
    assert db_file.exists()
