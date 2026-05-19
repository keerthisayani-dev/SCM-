from backend.utils.auth import hash_password, verify_password


def test_hashing_uses_random_salts_and_verification_still_succeeds() -> None:
    password = "Strong@123"

    first_hash = hash_password(password)
    second_hash = hash_password(password)

    assert first_hash != second_hash
    assert verify_password(password, first_hash) is True
    assert verify_password(password, second_hash) is True
