from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.security.token import decode_access_token


bearer_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        bearer_scheme
    ),
) -> dict:
    """
    Validate the Bearer token and return the authenticated
    user's identity and role.
    """

    token = credentials.credentials

    try:
        payload = decode_access_token(token)

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from exc

    username = payload.get("sub")
    role = payload.get("role")

    if not username or not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token payload.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    return {
        "username": username,
        "role": role,
    }


def require_roles(
    *allowed_roles: str,
) -> Callable:
    """
    Create a dependency that allows only the specified roles.
    """

    normalized_roles = {
        role.upper()
        for role in allowed_roles
    }

    def role_checker(
        current_user: dict = Depends(get_current_user),
    ) -> dict:

        user_role = current_user["role"].upper()

        if user_role not in normalized_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions.",
            )

        return current_user

    return role_checker