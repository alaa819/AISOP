from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str


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
    limit: int = Field(ge=1, le=500)
    offset: int = Field(ge=0)
    alerts: list[dict[str, Any]]


class SeverityStatistics(BaseModel):
    high: int
    medium: int
    low: int


class StatisticsResponse(BaseModel):
    total_alerts: int
    severity: SeverityStatistics