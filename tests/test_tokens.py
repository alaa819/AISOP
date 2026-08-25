import pytest

from app.core.security.token import (
    create_access_token,
    decode_access_token,
)


def test_create_and_decode_token():
    token = create_access_token(
        "test-user",
        "ADMIN",
    )

    payload = decode_access_token(token)

    assert payload["sub"] == "test-user"
    assert payload["role"] == "ADMIN"
    assert "iat" in payload
    assert "exp" in payload


def test_invalid_token_fails():
    with pytest.raises(Exception):
        decode_access_token(
            "this-is-not-a-valid-jwt",
        )