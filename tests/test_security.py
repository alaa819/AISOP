from app.core.security.password import (
    hash_password,
    verify_password,
)


def test_password_hashing():
    password = "StrongTestPassword123!"

    hashed_password = hash_password(password)

    assert hashed_password != password
    assert verify_password(
        password,
        hashed_password,
    )


def test_wrong_password_fails():
    password = "StrongTestPassword123!"
    wrong_password = "WrongPassword123!"

    hashed_password = hash_password(password)

    assert not verify_password(
        wrong_password,
        hashed_password,
    )