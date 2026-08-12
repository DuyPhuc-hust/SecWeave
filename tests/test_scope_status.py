from shared.models.signal import ScopeStatus


def test_scope_status_values():
    assert ScopeStatus.TARGET == "TARGET"
    assert ScopeStatus.UNKNOWN == "UNKNOWN"
    assert len(ScopeStatus) == 6


def test_scope_status_members():
    expected = {
        "TARGET",
        "AUTHORIZED_DEPENDENCY",
        "OBSERVE_ONLY",
        "CONTEXT_ONLY",
        "OUT_OF_SCOPE",
        "UNKNOWN",
    }
    actual = {member.value for member in ScopeStatus}
    assert actual == expected
