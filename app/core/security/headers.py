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

    # Swagger UI requires external assets from jsDelivr
    # and an inline initialization script.
    if request.url.path.startswith("/docs"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "font-src 'self' data: https://cdn.jsdelivr.net"
        )
    else:
        # Keep the normal application CSP strict.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'"
        )

    return response