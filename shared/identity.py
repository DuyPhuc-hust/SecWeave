from shared.models.entities import Authorization


def get_execution_identity(authorization: Authorization) -> str:
    """Identity Service (skeleton) — weekly plan W5: the identity used to
    execute an action MUST come only from an Authorization loaded via Gate 2
    — nothing in this code reads an environment variable or an operator's
    personal config as a substitute.

    This is the ONLY access point for execution identity in the whole
    codebase — anywhere that needs an identity to execute an action must go
    through here, not read os.environ or personal config directly elsewhere.
    """
    if not authorization.identity:
        raise ValueError(
            "Authorization chưa có identity nào được cấp qua Gate 2 — không có "
            "identity cá nhân nào được dùng thay thế khi thiếu."
        )
    return authorization.identity
