from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Alert:
    """
    Represents a normalized AISOP security alert.

    The Alert model is the common structure used by the detection,
    analysis, persistence, API, and future AI layers.
    """

    timestamp: str
    rule_id: str
    title: str
    severity: str
    risk_score: int

    host: str | None = None
    service: str | None = None
    description: str | None = None
    recommendation: str | None = None
    source_ip: str | None = None
    raw_event: Any = None
    analysis: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the Alert object into a dictionary.
        """

        return asdict(self)