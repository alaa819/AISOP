from pydantic import BaseModel


class SeverityStatistics(BaseModel):
    high: int
    medium: int
    low: int


class StatisticsResponse(BaseModel):
    total_alerts: int
    severity: SeverityStatistics