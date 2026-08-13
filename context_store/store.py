import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from shared.models.hypothesis import HypothesisResult, HypothesisStatus
from shared.models.signal import NormalizedSignal

DEFAULT_DB_PATH = ".secweave/context.db"


class SecurityContextStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS verified_observations (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                description TEXT NOT NULL,
                verified_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hypotheses (
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
        self._conn.commit()

    def get_verified_context(self, target_id: str) -> List[Dict[str, Any]]:
        cursor = self._conn.execute(
            "SELECT id, description, verified_at FROM verified_observations WHERE target_id = ?",
            (target_id,),
        )
        return [
            {"id": row[0], "description": row[1], "verified_at": row[2]}
            for row in cursor.fetchall()
        ]

    def record_hypothesis(self, result: HypothesisResult, signal: NormalizedSignal) -> None:
        is_hypothesis = result.status == HypothesisStatus.HYPOTHESIS
        self._conn.execute(
            """
            INSERT INTO hypotheses (
                hypothesis_id, signal_id, source_tool, status,
                expected_behavior, suspected_behavior, observation_criteria,
                reason, coverage, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.hypothesis.hypothesis_id if is_hypothesis else None,
                signal.signal_id,
                signal.source.tool,
                result.status.value,
                result.hypothesis.expected_behavior if is_hypothesis else None,
                result.hypothesis.suspected_behavior if is_hypothesis else None,
                result.hypothesis.observation_criteria if is_hypothesis else None,
                result.reason,
                signal.source.coverage.value,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Dict[str, Any]]:
        cursor = self._conn.execute(
            """
            SELECT hypothesis_id, signal_id, source_tool, status, expected_behavior,
                   suspected_behavior, observation_criteria, reason, coverage, created_at
            FROM hypotheses WHERE hypothesis_id = ?
            """,
            (hypothesis_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        columns = (
            "hypothesis_id", "signal_id", "source_tool", "status", "expected_behavior",
            "suspected_behavior", "observation_criteria", "reason", "coverage", "created_at",
        )
        return dict(zip(columns, row))

    def close(self) -> None:
        self._conn.close()
