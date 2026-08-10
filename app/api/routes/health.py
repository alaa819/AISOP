from datetime import datetime, timezone

from fastapi import APIRouter

from app.api.schemas import HealthResponse


router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
)
def health_check() -> HealthResponse:
    """
    Return the current API health status.
    """

    return HealthResponse(
        status="healthy",
        service="AISOP API",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )