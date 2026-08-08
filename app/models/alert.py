from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Alert:
    timestamp: str
    host: str
    service: str
    rule_id: str
    title: str
    description: str
    severity: str
    risk_score: int
    recommendation: str
    source_ip: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)