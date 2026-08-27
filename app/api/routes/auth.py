from fastapi import APIRouter, HTTPException, status

from app.api.schemas.auth import (
    LoginRequest,
    TokenResponse,
)
from app.services.auth import authenticate_user


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login(request: LoginRequest):
    """
    Authenticate a user and return a JWT access token.
    """

    token = authenticate_user(
        request.username,
        request.password,
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