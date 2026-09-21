from fastapi import APIRouter, HTTPException, Request, status

from app.api.schemas.auth import (
    LoginRequest,
    TokenResponse,
)
from app.core.security.rate_limit import limiter
from app.services.auth import authenticate_user


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/login",
    response_model=TokenResponse,
)
@limiter.limit("5/minute")
def login(
    request: Request,
    credentials: LoginRequest,
):
    """
    Authenticate a user and return a JWT access token.

    Rate limited to 5 requests per minute per client IP.
    """

    token = authenticate_user(
        credentials.username,
        credentials.password,
    )

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
    )