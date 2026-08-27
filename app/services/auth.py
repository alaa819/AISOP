from app.core.security.password import verify_password
from app.core.security.token import create_access_token
from app.database.user_repository import UserRepository


repository = UserRepository()


def authenticate_user(
    username: str,
    password: str,
) -> str | None:
    """
    Authenticate a user using the database.

    Returns a JWT access token when authentication succeeds.
    Returns None when authentication fails.
    """

    user = repository.get_user_by_username(username)

    if user is None:
        return None

    if not user["is_active"]:
        return None

    if not verify_password(
        password,
        user["password_hash"],
    ):
        return None

    return create_access_token(
        subject=user["username"],
        role=user["role"],
    )