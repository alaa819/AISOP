from app.core.security.password import verify_password
from app.core.security.token import create_access_token


DEVELOPMENT_USER = {
    "username": "ala",
    "role": "ADMIN",
    "password_hash": (
        "$argon2id$v=19$m=65536,t=3,p=4$XS95/WfQ2fJgmtspohF1ug$FBz3PSn1N893AOVsw4CwI1R2/KyuhV1ulZ0f7u/hKr8"
    ),
}


def authenticate_user(
    username: str,
    password: str,
) -> str | None:
    """
    Authenticate a development user and return a JWT.
    """

    if username != DEVELOPMENT_USER["username"]:
        return None

    if not verify_password(
        password,
        DEVELOPMENT_USER["password_hash"],
    ):
        return None

    return create_access_token(
        subject=username,
        role=DEVELOPMENT_USER["role"],
    )