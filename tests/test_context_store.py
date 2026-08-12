from context_store.store import SecurityContextStore


def test_get_verified_context_empty_by_default():
    store = SecurityContextStore()
    assert store.get_verified_context("target_1") == []
    store.close()


def test_get_verified_context_filters_by_target_id():
    store = SecurityContextStore()
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
