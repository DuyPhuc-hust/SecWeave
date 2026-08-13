from shared.id_generator import generate_id


def test_generate_id_has_correct_prefix():
    assert generate_id("sig").startswith("sig_")
    assert generate_id("hyp").startswith("hyp_")


def test_generate_id_is_unique_per_call():
    ids = {generate_id("sig") for _ in range(1000)}
    assert len(ids) == 1000
