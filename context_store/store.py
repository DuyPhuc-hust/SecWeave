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
            try:
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                # Real gap found via independent review: this raised a
                # plain OSError (e.g. a parent path component is an
                # existing regular file, not a directory) — every cli.py
                # call site only catches sqlite3.Error around construction,
                # so this used to escape uncaught and dump a raw traceback
                # (leaking local file paths) instead of a clean error.
                # Re-raised as sqlite3.OperationalError (a sqlite3.Error
                # subclass) so "the store couldn't be opened" has exactly
                # ONE exception type to catch, regardless of whether the
                # failure was directory creation or the sqlite connection
                # itself.
                raise sqlite3.OperationalError(
                    f"Không tạo được thư mục chứa Context Store tại '{db_path}': {exc}"
                ) from exc
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
                location TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        self._migrate_add_missing_columns()
        self._conn.commit()

    def _migrate_add_missing_columns(self) -> None:
        # "CREATE TABLE IF NOT EXISTS" doesn't add new columns to a table
        # that already existed before (e.g. a .secweave/context.db created by
        # an older version of the code) — without this column, every
        # subsequent record_hypothesis()/get_hypothesis() would break with
        # "no such column" instead of a clear error. The MVP doesn't need a
        # full migration framework yet, just enough to not lose old data
        # when the schema adds a new column.
        existing_columns = {row[1] for row in self._conn.execute("PRAGMA table_info(hypotheses)")}
        if "location" not in existing_columns:
            self._conn.execute("ALTER TABLE hypotheses ADD COLUMN location TEXT")

    def get_verified_context(self, target_id: str) -> List[Dict[str, Any]]:
        # Real gap found via independent review: unlike record_hypothesis(),
        # this had zero exception handling — a real sqlite failure (e.g.
        # "database is locked" under contention) used to escape uncaught.
        try:
            cursor = self._conn.execute(
                "SELECT id, description, verified_at FROM verified_observations WHERE target_id = ?",
                (target_id,),
            )
            return [
                {"id": row[0], "description": row[1], "verified_at": row[2]}
                for row in cursor.fetchall()
            ]
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không đọc được verified context cho target_id '{target_id}': {exc}") from exc

    def record_hypothesis(self, result: HypothesisResult, signal: NormalizedSignal) -> None:
        is_hypothesis = result.status == HypothesisStatus.HYPOTHESIS
        try:
            self._conn.execute(
                """
                INSERT INTO hypotheses (
                    hypothesis_id, signal_id, source_tool, status,
                    expected_behavior, suspected_behavior, observation_criteria,
                    reason, coverage, location, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    result.hypothesis.provenance.location.model_dump_json() if is_hypothesis else None,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không ghi được hypothesis vào Context Store: {exc}") from exc

    _HYPOTHESIS_COLUMNS = (
        "hypothesis_id", "signal_id", "source_tool", "status", "expected_behavior",
        "suspected_behavior", "observation_criteria", "reason", "coverage", "location",
        "created_at",
    )

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Dict[str, Any]]:
        try:
            cursor = self._conn.execute(
                f"SELECT {', '.join(self._HYPOTHESIS_COLUMNS)} FROM hypotheses WHERE hypothesis_id = ?",
                (hypothesis_id,),
            )
            row = cursor.fetchone()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không đọc được hypothesis_id '{hypothesis_id}': {exc}") from exc
        if row is None:
            return None
        return dict(zip(self._HYPOTHESIS_COLUMNS, row))

    def get_hypotheses_by_signal_id(self, signal_id: str) -> List[Dict[str, Any]]:
        # A NOT_VERIFIABLE record has no hypothesis_id (no Hypothesis was ever
        # created), so get_hypothesis() can't look it up — querying by
        # signal_id is the only way to retrieve "a hypothesis that was
        # rejected along with its reason" (SPEC §4.6).
        try:
            cursor = self._conn.execute(
                f"SELECT {', '.join(self._HYPOTHESIS_COLUMNS)} FROM hypotheses "
                "WHERE signal_id = ? ORDER BY row_id",
                (signal_id,),
            )
            return [dict(zip(self._HYPOTHESIS_COLUMNS, row)) for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            raise RuntimeError(f"Không đọc được hypotheses cho signal_id '{signal_id}': {exc}") from exc

    def close(self) -> None:
        self._conn.close()
