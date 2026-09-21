from collections.abc import Callable

from fastapi import Request
from fastapi.responses import Response


async def security_headers_middleware(
    request: Request,
    call_next: Callable,
) -> Response:
    """
    Add security-related HTTP response headers.
    """

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'"
    )

    return response