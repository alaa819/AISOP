from typing import Any

from fastapi import APIRouter, Depends

from app.api.dependencies import require_roles
from app.api.schemas import StatisticsResponse
from app.database.repository import AlertRepository


router = APIRouter()

repository = AlertRepository()


@router.get(
    "/statistics",
    response_model=StatisticsResponse,
)
def get_statistics(
    current_user: dict = Depends(
        require_roles(
            "ADMIN",
            "ANALYST",
        )
    ),
) -> dict[str, Any]:
    """
    Return high-level AISOP alert statistics.

    Requires ADMIN or ANALYST permissions.
    """

    total = repository.count_alerts()

    high = len(
        repository.get_alerts_by_severity(
            severity="HIGH",
            limit=500,
        )
    )

    medium = len(
        repository.get_alerts_by_severity(
            severity="MEDIUM",
            limit=500,
        )
    )

    low = len(
        repository.get_alerts_by_severity(
            severity="LOW",
            limit=500,
        )
    )

    return {
        "total_alerts": total,
        "severity": {
            "high": high,
            "medium": medium,
            "low": low,
        },
    }