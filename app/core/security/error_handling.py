import logging

from fastapi import Request
from fastapi.responses import JSONResponse


logger = logging.getLogger("aisop.security")


async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """
    Handle unexpected application errors safely.

    The full exception is logged server-side, while the API
    returns a generic error message to the client.
    """

    request_id = getattr(
        request.state,
        "request_id",
        "unknown",
    )

    logger.exception(
        "Unhandled exception | "
        "request_id=%s | "
        "method=%s | "
        "path=%s",
        request_id,
        request.method,
        request.url.path,
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error.",
            "request_id": request_id,
        },
    )