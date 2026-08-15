from shared.models.entities import Authorization


def get_execution_identity(authorization: Authorization) -> str:
    """Identity Service (skeleton) — weekly plan W5: validates that an
    Authorization loaded via Gate 2 actually carries an identity, instead of
    silently falling back to an environment variable or an operator's
    personal config.

    STALE CLAIM REMOVED (found via review): this docstring used to say it's
    "the ONLY access point for execution identity in the whole codebase" —
    no longer true. `evidence_harness/harness.py`'s `capture()`/`login()`
    now take a plain caller-supplied `identity: str` directly, per call, and
    never touch `Authorization.identity` at all — a deliberate consequence
    of a run needing MULTIPLE identities (e.g. "alice"/"bob") to make
    positive_control/denied_control meaningful, which a single
    `Authorization.identity: Optional[str]` field can't represent 1:1
    anyway. This function is currently unused in production (only its own
    test exercises it) — kept as a narrow validator for the
    single-identity-per-Authorization case, not an enforced gate every
    identity must pass through.
    """
    if not authorization.identity:
        raise ValueError(
            "Authorization chưa có identity nào được cấp qua Gate 2 — không có "
            "identity cá nhân nào được dùng thay thế khi thiếu."
        )
    return authorization.identity
