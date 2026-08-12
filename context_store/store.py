import sqlite3
from typing import Any, Dict, List


class SecurityContextStore:
    def __init__(self, db_path: str = ":memory:") -> None:
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

    def close(self) -> None:
        self._conn.close()
