import uuid
from collections.abc import Callable

from fastapi import Request
from fastapi.responses import Response


REQUEST_ID_HEADER = "X-Request-ID"


async def request_id_middleware(
    request: Request,
    call_next: Callable,
) -> Response:
    """
    Add a unique request ID to every API request.

    If the client provides an X-Request-ID header, it is reused.
    Otherwise, AISOP generates a new UUID.
    """

    request_id = request.headers.get(
        REQUEST_ID_HEADER
    )

    if not request_id:
        request_id = str(uuid.uuid4())

    request.state.request_id = request_id

    response = await call_next(request)

    response.headers[
        REQUEST_ID_HEADER
    ] = request_id

    return response