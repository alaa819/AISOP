from fastapi import APIRouter, HTTPException, Request, status

from app.api.schemas.auth import (
    LoginRequest,
    TokenResponse,
)
from app.core.security.audit import log_audit_event
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

    client_ip = request.client.host if request.client else "unknown"

    token = authenticate_user(
        credentials.username,
        credentials.password,
    )

    if token is None:
        log_audit_event(
            username=credentials.username,
            action="LOGIN",
            result="FAILURE",
            ip_address=client_ip,
            endpoint=request.url.path,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    log_audit_event(
        username=credentials.username,
        action="LOGIN",
        result="SUCCESS",
        ip_address=client_ip,
        endpoint=request.url.path,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
    )