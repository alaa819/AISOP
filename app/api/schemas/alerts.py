from typing import Any

from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: int
    timestamp: str | None = None
    host: str | None = None
    service: str | None = None
    rule_id: str | None = None
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    risk_score: int | float | None = None
    recommendation: str | None = None
    source_ip: str | None = None
    raw_event: str | None = None
    analysis: str | None = None
    created_at: str | None = None


class AlertListResponse(BaseModel):
    count: int
    limit: int
    offset: int
    alerts: list[dict[str, Any]]