from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import require_roles
from app.api.schemas import AlertListResponse
from app.database.repository import AlertRepository


router = APIRouter()

repository = AlertRepository()


@router.get(
    "/alerts",
    response_model=AlertListResponse,
)
def get_alerts(
    severity: str | None = Query(
        default=None,
        description="Filter alerts by severity.",
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
        description="Maximum number of alerts to return.",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Number of alerts to skip.",
    ),
    current_user: dict = Depends(
        require_roles(
            "ADMIN",
            "ANALYST",
            "VIEWER",
        )
    ),
) -> dict[str, Any]:
    """
    Retrieve persisted AISOP security alerts.

    Requires an authenticated user with
    ADMIN, ANALYST, or VIEWER role.
    """

    if severity:
        severity = severity.upper()

        allowed_severities = {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }

        if severity not in allowed_severities:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Invalid severity. "
                    "Use LOW, MEDIUM, HIGH, or CRITICAL."
                ),
            )

        alerts = repository.get_alerts_by_severity(
            severity=severity,
            limit=limit,
        )

    else:
        alerts = repository.get_alerts(
            limit=limit,
            offset=offset,
        )

    return {
        "count": len(alerts),
        "limit": limit,
        "offset": offset,
        "alerts": alerts,
    }


@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: int,
    current_user: dict = Depends(
        require_roles(
            "ADMIN",
            "ANALYST",
            "VIEWER",
        )
    ),
) -> dict[str, Any]:
    """
    Retrieve one security alert by ID.

    Requires an authenticated user with
    ADMIN, ANALYST, or VIEWER role.
    """

    if alert_id <= 0:
        raise HTTPException(
            status_code=400,
            detail="alert_id must be greater than zero.",
        )

    alert = repository.get_alert(alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail=f"Alert {alert_id} was not found.",
        )

    return alert