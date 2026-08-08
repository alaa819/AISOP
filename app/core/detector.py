from collections import Counter
from typing import List

from app.models.alert import Alert
from app.rules.rules import RULES
from app.core.scorer import RiskScorer


class DetectionEngine:
    """
    Matches structured log events against security rules.
    """

    def __init__(self, rules=None):
        self.rules = rules or RULES
        self.scorer = RiskScorer()

    def detect(self, parsed_logs: List[dict]) -> List[Alert]:

        alerts = []

        for rule in self.rules:

            matching_logs = [
                log
                for log in parsed_logs
                if rule["pattern"].lower()
                in log["message"].lower()
            ]

            occurrence_count = len(matching_logs)

            for log in matching_logs:

                risk_score = self.scorer.calculate(
                    rule["base_score"],
                    occurrence_count,
                )

                severity = self.scorer.severity(risk_score)

                alerts.append(
                    Alert(
                        timestamp=log["timestamp"],
                        host=log["host"],
                        service=log["service"],
                        rule_id=rule["id"],
                        title=rule["name"],
                        description=rule["description"],
                        severity=severity,
                        risk_score=risk_score,
                        recommendation=rule["recommendation"],
                    )
                )

        return alerts